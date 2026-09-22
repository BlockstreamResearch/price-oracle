use secp256k1_zkp::PublicKey;
use sqlx::{Any, AnyPool, Row, Transaction};

use crate::NetworkAsset;

pub(crate) const CANONICAL_JOURNAL_RETENTION_BLOCKS: u64 = 144;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingChainLock {
    pub member: [u8; 32],
    pub amount: u64,
    pub block_height: u64,
    pub transaction: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalBlock {
    pub height: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryState {
    pub recovering: bool,
    pub fork_height: Option<u64>,
    pub safe_halted: bool,
    pub halt_reason: Option<String>,
    pub migration_paused: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedMemberMigration {
    pub request_hash: [u8; 32],
    pub block_height: u64,
    pub block_hash: [u8; 32],
    pub asset_kind: String,
    pub previous_script: Vec<u8>,
    pub previous_data: Option<Vec<u8>>,
    pub next_script: Vec<u8>,
    pub next_data: Option<Vec<u8>>,
    pub previous_members: Vec<[u8; 32]>,
    pub next_members: Vec<[u8; 32]>,
}

#[derive(Clone)]
pub struct ChainStore {
    pool: AnyPool,
}

impl ChainStore {
    pub(crate) fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    pub(crate) async fn begin(&self) -> Result<Transaction<'_, Any>, sqlx::Error> {
        self.pool.begin().await
    }

    pub async fn tip(&self) -> Result<Option<CanonicalBlock>, sqlx::Error> {
        sqlx::query(
            "SELECT block_height, block_hash, parent_hash FROM canonical_blocks \
             ORDER BY block_height DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?
        .map(decode_block)
        .transpose()
    }

    pub async fn blocks_descending(&self) -> Result<Vec<CanonicalBlock>, sqlx::Error> {
        sqlx::query(
            "SELECT block_height, block_hash, parent_hash FROM canonical_blocks \
             ORDER BY block_height DESC",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(decode_block)
        .collect()
    }

    pub(crate) async fn record_block(
        transaction: &mut Transaction<'_, Any>,
        block: &CanonicalBlock,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO canonical_blocks (block_height, block_hash, parent_hash) \
             VALUES ($1, $2, $3)",
        )
        .bind(encode_u64(block.height)?)
        .bind(block.hash.to_vec())
        .bind(block.parent_hash.to_vec())
        .execute(&mut **transaction)
        .await?;
        let first_retained = block
            .height
            .saturating_add(1)
            .saturating_sub(CANONICAL_JOURNAL_RETENTION_BLOCKS);
        sqlx::query("DELETE FROM canonical_blocks WHERE block_height < $1")
            .bind(encode_u64(first_retained)?)
            .execute(&mut **transaction)
            .await?;
        Ok(())
    }

    pub(crate) async fn record_asset_transition(
        transaction: &mut Transaction<'_, Any>,
        block: &CanonicalBlock,
        current: &NetworkAsset,
        renewed: &NetworkAsset,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO network_asset_chain_history \
             (block_height, block_hash, asset_kind, previous_script, previous_data, \
              next_script, next_data) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(encode_u64(block.height)?)
        .bind(block.hash.to_vec())
        .bind(&current.kind)
        .bind(&current.contract_script)
        .bind(&current.contract_data)
        .bind(&renewed.contract_script)
        .bind(&renewed.contract_data)
        .execute(&mut **transaction)
        .await?;
        Ok(())
    }

    pub async fn recovery_state(&self) -> Result<RecoveryState, sqlx::Error> {
        let row = sqlx::query(
            "SELECT recovering, fork_height, safe_halted, halt_reason, migration_paused \
             FROM chain_recovery_state WHERE id = 1",
        )
        .fetch_one(&self.pool)
        .await?;
        let fork_height = row
            .try_get::<Option<i64>, _>("fork_height")?
            .map(decode_u64)
            .transpose()?;

        Ok(RecoveryState {
            recovering: row.try_get::<i64, _>("recovering")? != 0,
            fork_height,
            safe_halted: row.try_get::<i64, _>("safe_halted")? != 0,
            halt_reason: row.try_get("halt_reason")?,
            migration_paused: row.try_get::<i64, _>("migration_paused")? != 0,
        })
    }

    pub async fn set_migration_paused(&self, paused: bool) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE chain_recovery_state SET migration_paused = $1 WHERE id = 1")
            .bind(i64::from(paused))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn finalized_member_migrations(
        &self,
    ) -> Result<Vec<FinalizedMemberMigration>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT request_hash, block_height, block_hash, asset_kind, previous_script, \
             previous_data, next_script, next_data FROM network_member_migrations \
             ORDER BY block_height, request_hash",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut migrations = Vec::with_capacity(rows.len());
        for row in rows {
            let request_hash = decode_hash(row.try_get("request_hash")?)?;
            migrations.push(FinalizedMemberMigration {
                request_hash,
                block_height: decode_u64(row.try_get("block_height")?)?,
                block_hash: decode_hash(row.try_get("block_hash")?)?,
                asset_kind: row.try_get("asset_kind")?,
                previous_script: row.try_get("previous_script")?,
                previous_data: row.try_get("previous_data")?,
                next_script: row.try_get("next_script")?,
                next_data: row.try_get("next_data")?,
                previous_members: self.migration_members(request_hash, "previous").await?,
                next_members: self.migration_members(request_hash, "next").await?,
            });
        }
        Ok(migrations)
    }

    async fn migration_members(
        &self,
        request_hash: [u8; 32],
        snapshot_kind: &str,
    ) -> Result<Vec<[u8; 32]>, sqlx::Error> {
        sqlx::query(
            "SELECT public_key FROM network_member_migration_peers \
             WHERE request_hash = $1 AND snapshot_kind = $2 ORDER BY peer_order",
        )
        .bind(request_hash.to_vec())
        .bind(snapshot_kind)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| {
            let encoded: String = row.try_get("public_key")?;
            let bytes =
                hex::decode(&encoded).map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
            let public_key = PublicKey::from_slice(&bytes)
                .map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
            Ok(public_key.x_only_public_key().0.serialize())
        })
        .collect()
    }

    pub async fn set_recovering(&self, fork_height: u64) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE chain_recovery_state SET recovering = 1, fork_height = $1 WHERE id = 1",
        )
        .bind(encode_u64(fork_height)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn safe_halt(&self, reason: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE chain_recovery_state SET recovering = 1, safe_halted = 1, halt_reason = $1 \
             WHERE id = 1",
        )
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn finish_recovery(&self) -> Result<(), sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("DELETE FROM chain_recovery_droplet_locks")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "UPDATE chain_recovery_state SET recovering = 0, fork_height = NULL WHERE id = 1",
        )
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await
    }

    pub async fn reset_projections(&self) -> Result<Vec<PendingChainLock>, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO chain_recovery_droplet_locks (xonly_pubkey, amount, block_height, transaction_bytes) \
             SELECT xonly_pubkey, exchange_amount, block_height, last_tx FROM droplets \
             WHERE exchange_locked = 1 AND last_tx IS NOT NULL \
             ON CONFLICT (xonly_pubkey) DO NOTHING",
        )
        .execute(&mut *transaction)
        .await?;
        let locks = sqlx::query(
            "SELECT xonly_pubkey, amount, block_height, transaction_bytes \
             FROM chain_recovery_droplet_locks ORDER BY xonly_pubkey",
        )
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .map(|row| {
            Ok(PendingChainLock {
                member: decode_hash(row.try_get("xonly_pubkey")?)?,
                amount: decode_u64(row.try_get("amount")?)?,
                block_height: decode_u64(row.try_get("block_height")?)?,
                transaction: row.try_get("transaction_bytes")?,
            })
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()?;

        let transitions = sqlx::query(
            "SELECT block_height, asset_kind, previous_script, previous_data \
             FROM network_asset_chain_history \
             UNION ALL \
             SELECT block_height, asset_kind, previous_script, previous_data \
             FROM network_member_migrations \
             ORDER BY block_height DESC",
        )
        .fetch_all(&mut *transaction)
        .await?;
        for transition in transitions {
            sqlx::query(
                "UPDATE network_assets SET contract_script = $1, contract_data = $2 \
                 WHERE kind = $3 AND status = 'active'",
            )
            .bind(transition.try_get::<Vec<u8>, _>("previous_script")?)
            .bind(transition.try_get::<Option<Vec<u8>>, _>("previous_data")?)
            .bind(transition.try_get::<String, _>("asset_kind")?)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query("DELETE FROM network_asset_chain_history")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM monitored_utxos")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM treasury_utxos")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM droplets")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM indexer_cursors")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM canonical_blocks")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "UPDATE network_user_requests SET status = 'processing', included_at_block = NULL, \
             included_block_hash = NULL WHERE status = 'included'",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE voting_requests SET execution_included_at_block = NULL, \
             execution_included_block_hash = NULL WHERE execution_confirmed = 0",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE storm_eye_renewals SET included_at_block = NULL, included_block_hash = NULL",
        )
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;

        Ok(locks)
    }
}

fn decode_block(row: sqlx::any::AnyRow) -> Result<CanonicalBlock, sqlx::Error> {
    Ok(CanonicalBlock {
        height: decode_u64(row.try_get("block_height")?)?,
        hash: decode_hash(row.try_get("block_hash")?)?,
        parent_hash: decode_hash(row.try_get("parent_hash")?)?,
    })
}

fn encode_u64(value: u64) -> Result<i64, sqlx::Error> {
    i64::try_from(value).map_err(|error| sqlx::Error::Encode(Box::new(error)))
}

fn decode_u64(value: i64) -> Result<u64, sqlx::Error> {
    u64::try_from(value).map_err(|error| sqlx::Error::Decode(Box::new(error)))
}

fn decode_hash(bytes: Vec<u8>) -> Result<[u8; 32], sqlx::Error> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        sqlx::Error::Decode(
            format!("expected 32-byte block hash, got {} bytes", bytes.len()).into(),
        )
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        NetworkAsset,
        db::{Database, network_asset::STORM_EYE_KIND},
    };

    use super::*;

    #[tokio::test]
    async fn projection_reset_preserves_pending_locks_until_recovery_finishes() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let chain = database.chain();
        let droplets = database.droplets();
        let member = [7; 32];

        let mut transaction = chain.begin().await.unwrap();
        ChainStore::record_block(
            &mut transaction,
            &CanonicalBlock {
                height: 42,
                hash: [4; 32],
                parent_hash: [3; 32],
            },
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
        droplets.credit(member, 1_000, 42).await.unwrap();
        assert!(
            droplets
                .lock_exchange(member, 500, 42, b"pending transaction")
                .await
                .unwrap()
        );

        chain.set_recovering(42).await.unwrap();
        let first = chain.reset_projections().await.unwrap();
        let second = chain.reset_projections().await.unwrap();

        assert_eq!(first, second);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].member, member);
        assert_eq!(first[0].amount, 500);
        assert_eq!(first[0].transaction, b"pending transaction");
        assert!(chain.tip().await.unwrap().is_none());
        assert!(droplets.balance(member).await.unwrap().is_none());
        assert!(chain.recovery_state().await.unwrap().recovering);

        chain.finish_recovery().await.unwrap();
        assert!(!chain.recovery_state().await.unwrap().recovering);
    }

    #[tokio::test]
    async fn canonical_journal_retains_only_the_reorg_window() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let chain = database.chain();

        for height in 0..CANONICAL_JOURNAL_RETENTION_BLOCKS + 6 {
            let mut transaction = chain.begin().await.unwrap();
            ChainStore::record_block(
                &mut transaction,
                &CanonicalBlock {
                    height,
                    hash: [height as u8; 32],
                    parent_hash: [height.saturating_sub(1) as u8; 32],
                },
            )
            .await
            .unwrap();
            transaction.commit().await.unwrap();
        }

        let blocks = chain.blocks_descending().await.unwrap();
        assert_eq!(blocks.len(), CANONICAL_JOURNAL_RETENTION_BLOCKS as usize);
        assert_eq!(blocks.last().unwrap().height, 6);
    }

    #[tokio::test]
    async fn safety_halt_survives_recovery_completion() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let chain = database.chain();

        chain
            .safe_halt("orphaned finalized migration")
            .await
            .unwrap();
        chain.finish_recovery().await.unwrap();

        let state = chain.recovery_state().await.unwrap();
        assert!(state.safe_halted);
        assert_eq!(
            state.halt_reason.as_deref(),
            Some("orphaned finalized migration")
        );
    }

    #[tokio::test]
    async fn reset_reverses_renewals_and_migrations_in_chain_order() {
        let database = Database::connect("sqlite::memory:", 1).await.unwrap();
        let chain = database.chain();
        database
            .network_assets()
            .insert_active(&NetworkAsset {
                kind: STORM_EYE_KIND.into(),
                name: "Storm Eye".into(),
                asset_id: [1; 32],
                reissuance_token_id: None,
                entropy: None,
                issuance_txid: [2; 32],
                contract_script: vec![0x54],
                contract_data: None,
                supply: 10_000,
                created_at_block: 1,
            })
            .await
            .unwrap();
        for (height, previous, next) in [(10_i64, 0x51, 0x52), (30, 0x53, 0x54)] {
            sqlx::query(
                "INSERT INTO network_asset_chain_history \
                 (block_height, block_hash, asset_kind, previous_script, next_script) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(height)
            .bind(vec![height as u8; 32])
            .bind(STORM_EYE_KIND)
            .bind(vec![previous])
            .bind(vec![next])
            .execute(&chain.pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO network_member_migrations \
             (request_hash, execution_txid, block_height, block_hash, asset_kind, \
              previous_script, next_script, previous_coordinator_public_key, next_coordinator_public_key) \
             VALUES ($1, $2, 20, $3, $4, $5, $6, $7, $7)",
        )
        .bind(vec![7; 32])
        .bind(vec![8; 32])
        .bind(vec![9; 32])
        .bind(STORM_EYE_KIND)
        .bind(vec![0x52])
        .bind(vec![0x53])
        .bind("02".repeat(33))
        .execute(&chain.pool)
        .await
        .unwrap();

        chain.reset_projections().await.unwrap();

        let asset = database
            .network_assets()
            .get(STORM_EYE_KIND)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(asset.contract_script, vec![0x51]);
    }
}
