use std::collections::HashSet;

use super::{decode_hash, decode_u64, encode_u64};
use sqlx::{Any, AnyPool, QueryBuilder, Row, Transaction};

const BURNING_BLOCKS: u64 = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedBlock {
    pub height: u64,
    pub hash: [u8; 32],
}

#[cfg(test)]
impl IndexedBlock {
    /// A block at `height` whose hash repeats the height's low byte.
    pub(crate) fn at(height: u64) -> Self {
        Self {
            height,
            hash: [height as u8; 32],
        }
    }
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
    /// A Verifier's Taproot internal key; `None` for a Tick.
    pub internal_key: Option<[u8; 32]>,
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

        Self::apply_block_in(&mut transaction, block, issued, spent, active_blocks).await?;
        Self::record_cursor(&mut transaction, rule_set, block).await?;
        transaction.commit().await
    }

    /// Returns how many burns reverted to `expired` because their transaction
    /// was not confirmed within `BURNING_BLOCKS`.
    pub(crate) async fn apply_block_in(
        transaction: &mut Transaction<'_, Any>,
        block: &IndexedBlock,
        issued: &[MonitoredUtxo],
        spent: &[([u8; 32], u32, [u8; 32])],
        active_blocks: u64,
    ) -> Result<u64, sqlx::Error> {
        for utxo in issued {
            sqlx::query(
                "INSERT INTO monitored_utxos \
                 (txid, output_index, asset_kind, amount, script_pubkey, auth_method, auth_data, \
                  account_owner_pubkey, burning_fee_txid, burning_fee_output_index, block_height, \
                  status, status_block_height, burn_txid, internal_key) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'active', $11, NULL, $12) \
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
            .bind(utxo.internal_key.map(|key| key.to_vec()))
            .execute(&mut **transaction)
            .await?;
        }

        for (txid, output_index, _) in spent {
            sqlx::query("DELETE FROM monitored_utxos WHERE txid = $1 AND output_index = $2")
                .bind(txid.to_vec())
                .bind(i64::from(*output_index))
                .execute(&mut **transaction)
                .await?;
        }

        sqlx::query(
            "UPDATE monitored_utxos SET status = 'expired', status_block_height = $1 \
             WHERE status = 'active' AND block_height + $2 <= $1",
        )
        .bind(encode_u64(block.height)?)
        .bind(encode_u64(active_blocks)?)
        .execute(&mut **transaction)
        .await?;
        let reverted = sqlx::query(
            "UPDATE monitored_utxos SET status = 'expired', status_block_height = $1, \
             burn_txid = NULL WHERE status = 'burning' AND status_block_height + $2 <= $1",
        )
        .bind(encode_u64(block.height)?)
        .bind(encode_u64(BURNING_BLOCKS)?)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        Ok(reverted)
    }

    pub async fn count_by_status(&self) -> Result<Vec<(String, u64)>, sqlx::Error> {
        sqlx::query("SELECT status, COUNT(*) AS count FROM monitored_utxos GROUP BY status")
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|row| Ok((row.try_get("status")?, decode_u64(row.try_get("count")?)?)))
            .collect()
    }

    /// The issue height of the oldest Tick or Verifier that expired and is still
    /// not burned.
    pub async fn oldest_unburned_block_height(&self) -> Result<Option<u64>, sqlx::Error> {
        sqlx::query(
            "SELECT MIN(block_height) AS height FROM monitored_utxos \
             WHERE status IN ('expired', 'burning')",
        )
        .fetch_one(&self.pool)
        .await?
        .try_get::<Option<i64>, _>("height")?
        .map(decode_u64)
        .transpose()
    }

    pub(crate) async fn record_cursor(
        transaction: &mut Transaction<'_, Any>,
        rule_set: &str,
        block: &IndexedBlock,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO indexer_cursors (rule_set, block_height, block_hash) VALUES ($1, $2, $3) \
             ON CONFLICT (rule_set) DO UPDATE SET block_height = $2, block_hash = $3",
        )
        .bind(rule_set)
        .bind(encode_u64(block.height)?)
        .bind(block.hash.to_vec())
        .execute(&mut **transaction)
        .await?;
        Ok(())
    }

    pub async fn list_expired(&self, limit: u32) -> Result<Vec<MonitoredUtxo>, sqlx::Error> {
        sqlx::query(
            "SELECT txid, output_index, asset_kind, amount, script_pubkey, auth_method, auth_data, \
             account_owner_pubkey, burning_fee_txid, burning_fee_output_index, block_height, status, \
             status_block_height, burn_txid, internal_key FROM monitored_utxos \
             WHERE status = 'expired' \
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

    pub async fn burning_reservations(
        &self,
        outpoints: &[([u8; 32], u32)],
    ) -> Result<Vec<bool>, sqlx::Error> {
        if outpoints.is_empty() {
            return Ok(Vec::new());
        }

        let mut query = QueryBuilder::<Any>::new("WITH requested (txid, output_index) AS (");
        query.push_values(0..outpoints.len(), |mut row, index| {
            row.push(format!("${}", index * 2 + 1))
                .push(format!("${}", index * 2 + 2));
        });
        query.push(
            ") SELECT txid, output_index FROM requested WHERE EXISTS (\
             SELECT 1 FROM monitored_utxos WHERE burning_fee_txid = requested.txid \
             AND burning_fee_output_index = requested.output_index \
             AND status IN ('active', 'expired', 'burning'))",
        );
        let mut statement = query.build();
        for (txid, output_index) in outpoints {
            statement = statement.bind(txid.to_vec()).bind(i64::from(*output_index));
        }

        let rows = statement.fetch_all(&self.pool).await?;
        let reserved = rows
            .into_iter()
            .map(|row| {
                Ok((
                    decode_hash(row.try_get("txid")?)?,
                    row.try_get::<i64, _>("output_index")?,
                ))
            })
            .collect::<Result<HashSet<_>, sqlx::Error>>()?;

        Ok(outpoints
            .iter()
            .map(|(txid, index)| reserved.contains(&(*txid, i64::from(*index))))
            .collect())
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

    pub async fn burning_txids(&self) -> Result<Vec<[u8; 32]>, sqlx::Error> {
        sqlx::query(
            "SELECT DISTINCT burn_txid FROM monitored_utxos \
             WHERE status = 'burning' AND burn_txid IS NOT NULL ORDER BY burn_txid",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| decode_hash(row.try_get("burn_txid")?))
        .collect()
    }

    pub async fn release_burning(
        &self,
        burn_txid: [u8; 32],
        block_height: u64,
    ) -> Result<u64, sqlx::Error> {
        Ok(sqlx::query(
            "UPDATE monitored_utxos SET status = 'expired', status_block_height = $1, \
             burn_txid = NULL WHERE status = 'burning' AND burn_txid = $2",
        )
        .bind(encode_u64(block_height)?)
        .bind(burn_txid.to_vec())
        .execute(&self.pool)
        .await?
        .rows_affected())
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
    let internal_key = row
        .try_get::<Option<Vec<u8>>, _>("internal_key")?
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
        internal_key,
        burning_fee_txid: decode_hash(row.try_get("burning_fee_txid")?)?,
        burning_fee_output_index: decode_u32(row.try_get("burning_fee_output_index")?)?,
        block_height: decode_u64(row.try_get("block_height")?)?,
        status: row.try_get("status")?,
        status_block_height: decode_u64(row.try_get("status_block_height")?)?,
        burn_txid,
    })
}

fn decode_u32(value: i64) -> Result<u32, sqlx::Error> {
    u32::try_from(value).map_err(|error| sqlx::Error::Decode(Box::new(error)))
}

#[cfg(test)]
mod tests;
