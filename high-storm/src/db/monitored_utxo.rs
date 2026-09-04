use sqlx::{AnyPool, Row};

const BURNING_BLOCKS: u64 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedBlock {
    pub height: u64,
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MonitoredUtxo {
    pub txid: [u8; 32],
    pub output_index: u32,
    pub asset_kind: String,
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
    pub auth_method: String,
    pub auth_data: Vec<u8>,
    pub account_owner_pubkey: [u8; 32],
    pub burning_fee_txid: [u8; 32],
    pub burning_fee_output_index: u32,
    pub block_height: u64,
    pub status: String,
    pub status_block_height: u64,
    pub burn_txid: Option<[u8; 32]>,
}

#[derive(Clone)]
pub struct MonitoredUtxoStore {
    pool: AnyPool,
}

impl MonitoredUtxoStore {
    pub(crate) fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    pub async fn cursor(&self, rule_set: &str) -> Result<Option<IndexedBlock>, sqlx::Error> {
        let Some(row) =
            sqlx::query("SELECT block_height, block_hash FROM indexer_cursors WHERE rule_set = $1")
                .bind(rule_set)
                .fetch_optional(&self.pool)
                .await?
        else {
            return Ok(None);
        };

        Ok(Some(IndexedBlock {
            height: decode_u64(row.try_get("block_height")?)?,
            hash: decode_hash(row.try_get("block_hash")?)?,
        }))
    }

    pub async fn apply_block(
        &self,
        rule_set: &str,
        block: &IndexedBlock,
        issued: &[MonitoredUtxo],
        spent: &[([u8; 32], u32, [u8; 32])],
        active_blocks: u64,
    ) -> Result<(), sqlx::Error> {
        let mut transaction = self.pool.begin().await?;

        for utxo in issued {
            sqlx::query(
                "INSERT INTO monitored_utxos \
                 (txid, output_index, asset_kind, amount, script_pubkey, auth_method, auth_data, \
                  account_owner_pubkey, burning_fee_txid, burning_fee_output_index, block_height, \
                  status, status_block_height, burn_txid) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'active', $11, NULL) \
                 ON CONFLICT (txid, output_index) DO NOTHING",
            )
            .bind(utxo.txid.to_vec())
            .bind(i64::from(utxo.output_index))
            .bind(&utxo.asset_kind)
            .bind(encode_u64(utxo.amount)?)
            .bind(&utxo.script_pubkey)
            .bind(&utxo.auth_method)
            .bind(&utxo.auth_data)
            .bind(utxo.account_owner_pubkey.to_vec())
            .bind(utxo.burning_fee_txid.to_vec())
            .bind(i64::from(utxo.burning_fee_output_index))
            .bind(encode_u64(utxo.block_height)?)
            .execute(&mut *transaction)
            .await?;
        }

        for (txid, output_index, _) in spent {
            sqlx::query("DELETE FROM monitored_utxos WHERE txid = $1 AND output_index = $2")
                .bind(txid.to_vec())
                .bind(i64::from(*output_index))
                .execute(&mut *transaction)
                .await?;
        }

        sqlx::query(
            "UPDATE monitored_utxos SET status = 'expired', status_block_height = $1 \
             WHERE status = 'active' AND block_height + $2 <= $1",
        )
        .bind(encode_u64(block.height)?)
        .bind(encode_u64(active_blocks)?)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE monitored_utxos SET status = 'expired', status_block_height = $1, \
             burn_txid = NULL WHERE status = 'burning' AND status_block_height + $2 <= $1",
        )
        .bind(encode_u64(block.height)?)
        .bind(encode_u64(BURNING_BLOCKS)?)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO indexer_cursors (rule_set, block_height, block_hash) VALUES ($1, $2, $3) \
             ON CONFLICT (rule_set) DO UPDATE SET block_height = $2, block_hash = $3",
        )
        .bind(rule_set)
        .bind(encode_u64(block.height)?)
        .bind(block.hash.to_vec())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await
    }

    pub async fn list_expired(&self, limit: u32) -> Result<Vec<MonitoredUtxo>, sqlx::Error> {
        sqlx::query(
            "SELECT txid, output_index, asset_kind, amount, script_pubkey, auth_method, auth_data, \
             account_owner_pubkey, burning_fee_txid, burning_fee_output_index, block_height, status, \
             status_block_height, burn_txid FROM monitored_utxos WHERE status = 'expired' \
             ORDER BY block_height, txid, output_index LIMIT $1",
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(decode_monitored_utxo)
        .collect()
    }

    pub async fn is_reserved_for_burning(
        &self,
        txid: [u8; 32],
        output_index: u32,
    ) -> Result<bool, sqlx::Error> {
        let reserved = sqlx::query(
            "SELECT 1 FROM monitored_utxos \
             WHERE burning_fee_txid = $1 AND burning_fee_output_index = $2 \
             AND status IN ('active', 'expired', 'burning') LIMIT 1",
        )
        .bind(txid.to_vec())
        .bind(i64::from(output_index))
        .fetch_optional(&self.pool)
        .await?;

        Ok(reserved.is_some())
    }

    pub async fn mark_burning(
        &self,
        utxos: &[([u8; 32], u32)],
        burn_txid: [u8; 32],
        block_height: u64,
    ) -> Result<u64, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        let mut updated = 0;
        for (txid, output_index) in utxos {
            let affected = sqlx::query(
                "UPDATE monitored_utxos SET status = 'burning', status_block_height = $1, \
                 burn_txid = $2 WHERE txid = $3 AND output_index = $4 \
                 AND (status = 'expired' OR (status = 'burning' AND burn_txid = $2))",
            )
            .bind(encode_u64(block_height)?)
            .bind(burn_txid.to_vec())
            .bind(txid.to_vec())
            .bind(i64::from(*output_index))
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if affected != 1 {
                transaction.rollback().await?;
                return Ok(0);
            }
            updated += affected;
        }
        transaction.commit().await?;
        Ok(updated)
    }

    pub async fn quarantine_unburnable(
        &self,
        utxos: &[([u8; 32], u32)],
        block_height: u64,
    ) -> Result<u64, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        let mut updated = 0;
        for (txid, output_index) in utxos {
            let affected = sqlx::query(
                "UPDATE monitored_utxos SET status = 'unburnable', status_block_height = $1, \
                 burn_txid = NULL WHERE txid = $2 AND output_index = $3 AND status = 'expired'",
            )
            .bind(encode_u64(block_height)?)
            .bind(txid.to_vec())
            .bind(i64::from(*output_index))
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if affected != 1 {
                transaction.rollback().await?;
                return Ok(0);
            }
            updated += affected;
        }
        transaction.commit().await?;
        Ok(updated)
    }
}

fn decode_monitored_utxo(row: sqlx::any::AnyRow) -> Result<MonitoredUtxo, sqlx::Error> {
    let burn_txid = row
        .try_get::<Option<Vec<u8>>, _>("burn_txid")?
        .map(decode_hash)
        .transpose()?;
    Ok(MonitoredUtxo {
        txid: decode_hash(row.try_get("txid")?)?,
        output_index: decode_u32(row.try_get("output_index")?)?,
        asset_kind: row.try_get("asset_kind")?,
        amount: decode_u64(row.try_get("amount")?)?,
        script_pubkey: row.try_get("script_pubkey")?,
        auth_method: row.try_get("auth_method")?,
        auth_data: row.try_get("auth_data")?,
        account_owner_pubkey: decode_hash(row.try_get("account_owner_pubkey")?)?,
        burning_fee_txid: decode_hash(row.try_get("burning_fee_txid")?)?,
        burning_fee_output_index: decode_u32(row.try_get("burning_fee_output_index")?)?,
        block_height: decode_u64(row.try_get("block_height")?)?,
        status: row.try_get("status")?,
        status_block_height: decode_u64(row.try_get("status_block_height")?)?,
        burn_txid,
    })
}

fn encode_u64(value: u64) -> Result<i64, sqlx::Error> {
    i64::try_from(value).map_err(|error| sqlx::Error::Encode(Box::new(error)))
}

fn decode_u64(value: i64) -> Result<u64, sqlx::Error> {
    u64::try_from(value).map_err(|error| sqlx::Error::Decode(Box::new(error)))
}

fn decode_u32(value: i64) -> Result<u32, sqlx::Error> {
    u32::try_from(value).map_err(|error| sqlx::Error::Decode(Box::new(error)))
}

fn decode_hash(value: Vec<u8>) -> Result<[u8; 32], sqlx::Error> {
    value
        .try_into()
        .map_err(|_| sqlx::Error::Decode("invalid hash length".into()))
}

#[cfg(test)]
mod tests {
    use crate::db::Database;

    use super::*;

    fn monitored(block_height: u64) -> MonitoredUtxo {
        MonitoredUtxo {
            txid: [1; 32],
            output_index: 2,
            asset_kind: "tick".into(),
            amount: 1_700_000_000,
            script_pubkey: vec![0x51],
            auth_method: "signature-auth".into(),
            auth_data: vec![2; 32],
            account_owner_pubkey: [4; 32],
            burning_fee_txid: [1; 32],
            burning_fee_output_index: 3,
            block_height,
            status: "active".into(),
            status_block_height: block_height,
            burn_txid: None,
        }
    }

    #[tokio::test]
    async fn advances_issued_utxo_lifecycle_from_confirmed_blocks() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.monitored_utxos();
        let issued = monitored(10);

        store
            .apply_block(
                "burning-v1",
                &IndexedBlock {
                    height: 10,
                    hash: [10; 32],
                },
                std::slice::from_ref(&issued),
                &[],
                60,
            )
            .await
            .unwrap();
        assert!(store.list_expired(10).await.unwrap().is_empty());
        assert!(
            store
                .is_reserved_for_burning(issued.burning_fee_txid, issued.burning_fee_output_index,)
                .await
                .unwrap()
        );
        assert!(
            !store
                .is_reserved_for_burning([9; 32], issued.burning_fee_output_index)
                .await
                .unwrap()
        );

        store
            .apply_block(
                "burning-v1",
                &IndexedBlock {
                    height: 70,
                    hash: [70; 32],
                },
                &[],
                &[],
                60,
            )
            .await
            .unwrap();
        let expired = store.list_expired(10).await.unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].txid, issued.txid);
        assert_eq!(expired[0].status, "expired");
        assert_eq!(expired[0].status_block_height, 70);
        assert!(
            store
                .is_reserved_for_burning(issued.burning_fee_txid, issued.burning_fee_output_index,)
                .await
                .unwrap()
        );

        assert_eq!(
            store
                .mark_burning(&[([1; 32], 2)], [3; 32], 70)
                .await
                .unwrap(),
            1
        );
        store
            .apply_block(
                "burning-v1",
                &IndexedBlock {
                    height: 75,
                    hash: [75; 32],
                },
                &[],
                &[],
                60,
            )
            .await
            .unwrap();
        assert_eq!(store.list_expired(10).await.unwrap()[0].status, "expired");
    }

    #[tokio::test]
    async fn marking_a_burn_batch_is_all_or_nothing() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.monitored_utxos();
        let first = monitored(1);
        let mut second = monitored(1);
        second.output_index = 3;
        store
            .apply_block(
                "burning-v1",
                &IndexedBlock {
                    height: 61,
                    hash: [6; 32],
                },
                &[first, second],
                &[],
                60,
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .mark_burning(&[([1; 32], 3)], [7; 32], 61)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .mark_burning(&[([1; 32], 3)], [7; 32], 61)
                .await
                .unwrap(),
            1
        );

        assert_eq!(
            store
                .mark_burning(&[([1; 32], 2), ([1; 32], 3)], [8; 32], 61)
                .await
                .unwrap(),
            0
        );
        assert_eq!(store.list_expired(10).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn quarantines_an_unburnable_group() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.monitored_utxos();
        let issued = monitored(1);
        store
            .apply_block(
                "burning-v1",
                &IndexedBlock {
                    height: 61,
                    hash: [6; 32],
                },
                std::slice::from_ref(&issued),
                &[],
                60,
            )
            .await
            .unwrap();

        assert_eq!(
            store
                .quarantine_unburnable(&[(issued.txid, issued.output_index)], 61)
                .await
                .unwrap(),
            1
        );
        assert!(store.list_expired(10).await.unwrap().is_empty());
        assert!(
            !store
                .is_reserved_for_burning(issued.burning_fee_txid, issued.burning_fee_output_index,)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn confirmed_spends_delete_ticks_and_release_the_shared_reserve() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let store = database.monitored_utxos();
        let first = monitored(1);
        let mut second = monitored(1);
        second.output_index = 4;
        store
            .apply_block(
                "burning-v1",
                &IndexedBlock {
                    height: 1,
                    hash: [1; 32],
                },
                &[first.clone(), second.clone()],
                &[],
                60,
            )
            .await
            .unwrap();

        store
            .apply_block(
                "burning-v1",
                &IndexedBlock {
                    height: 2,
                    hash: [2; 32],
                },
                &[],
                &[(first.txid, first.output_index, [8; 32])],
                60,
            )
            .await
            .unwrap();
        assert!(
            store
                .is_reserved_for_burning(first.burning_fee_txid, first.burning_fee_output_index,)
                .await
                .unwrap()
        );

        store
            .apply_block(
                "burning-v1",
                &IndexedBlock {
                    height: 3,
                    hash: [3; 32],
                },
                &[],
                &[(second.txid, second.output_index, [9; 32])],
                60,
            )
            .await
            .unwrap();
        assert!(
            !store
                .is_reserved_for_burning(first.burning_fee_txid, first.burning_fee_output_index,)
                .await
                .unwrap()
        );
        let remaining: i64 = sqlx::query("SELECT COUNT(*) AS count FROM monitored_utxos")
            .fetch_one(&store.pool)
            .await
            .unwrap()
            .try_get("count")
            .unwrap();
        assert_eq!(remaining, 0);
    }
}
