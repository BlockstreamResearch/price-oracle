use sqlx::{Any, AnyPool, Row, Transaction};

use super::monitored_utxo::{IndexedBlock, MonitoredUtxoStore};
use super::{decode_hash, decode_u64, encode_u64};

/// A credit repays any deficit before it adds to the balance.
const CREDIT_SQL: &str = "INSERT INTO droplets (xonly_pubkey, amount, block_height) VALUES ($1, $2, $3) \
     ON CONFLICT (xonly_pubkey) DO UPDATE SET \
     amount = droplets.amount + CASE WHEN excluded.amount > droplets.deficit \
         THEN excluded.amount - droplets.deficit ELSE 0 END, \
     deficit = CASE WHEN excluded.amount > droplets.deficit \
         THEN 0 ELSE droplets.deficit - excluded.amount END, \
     block_height = excluded.block_height";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreasuryTransaction {
    pub txid: [u8; 32],
    pub inputs: Vec<([u8; 32], u32)>,
    pub outputs: Vec<(u32, u64)>,
    pub deposit_member: Option<[u8; 32]>,
    pub exchange_member: Option<[u8; 32]>,
}

#[derive(Debug, thiserror::Error)]
pub enum DropletError {
    #[error("Droplets database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("invalid Treasury transaction: {0}")]
    Invalid(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DropletBalance {
    pub xonly_pubkey: [u8; 32],
    pub amount: u64,
    pub block_height: u64,
    pub exchange_locked: bool,
    pub last_tx: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DropletExchangeRequest {
    pub xonly_pubkey: [u8; 32],
    pub transaction: Vec<u8>,
    pub signing_hash: [u8; 32],
    pub requested_at_block: u64,
    pub status: String,
    pub completed_txid: Option<[u8; 32]>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreasuryUtxo {
    pub txid: [u8; 32],
    pub output_index: u32,
    pub amount: u64,
}

#[derive(Clone)]
pub struct DropletStore {
    pool: AnyPool,
}

impl DropletStore {
    pub(crate) fn new(pool: AnyPool) -> Self {
        Self { pool }
    }

    pub async fn credit(
        &self,
        xonly_pubkey: [u8; 32],
        amount: u64,
        block_height: u64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(CREDIT_SQL)
            .bind(xonly_pubkey.to_vec())
            .bind(encode_u64(amount)?)
            .bind(encode_u64(block_height)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The block whose Droplets accounting failed, and why; exchanges stay refused until a rebuild.
    pub async fn ledger_halt(&self) -> Result<Option<(u64, String)>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT droplets_halt_height, droplets_halt_reason FROM chain_recovery_state WHERE id = 1",
        )
        .fetch_one(&self.pool)
        .await?;
        let Some(height) = row.try_get::<Option<i64>, _>("droplets_halt_height")? else {
            return Ok(None);
        };
        Ok(Some((
            decode_u64(height)?,
            row.try_get::<Option<String>, _>("droplets_halt_reason")?
                .unwrap_or_default(),
        )))
    }

    pub(crate) async fn halt_ledger_in(
        transaction: &mut Transaction<'_, Any>,
        block_height: u64,
        reason: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE chain_recovery_state SET droplets_halt_height = $1, droplets_halt_reason = $2 \
             WHERE id = 1",
        )
        .bind(encode_u64(block_height)?)
        .bind(reason)
        .execute(&mut **transaction)
        .await?;
        Ok(())
    }

    pub async fn balance(
        &self,
        xonly_pubkey: [u8; 32],
    ) -> Result<Option<DropletBalance>, sqlx::Error> {
        sqlx::query(
            "SELECT xonly_pubkey, amount, block_height, exchange_locked, last_tx \
             FROM droplets WHERE xonly_pubkey = $1",
        )
        .bind(xonly_pubkey.to_vec())
        .fetch_optional(&self.pool)
        .await?
        .map(decode_balance)
        .transpose()
    }

    pub async fn locked(&self) -> Result<Vec<DropletBalance>, sqlx::Error> {
        sqlx::query(
            "SELECT xonly_pubkey, amount, block_height, exchange_locked, last_tx \
             FROM droplets WHERE exchange_locked = 1 ORDER BY xonly_pubkey",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(decode_balance)
        .collect()
    }

    pub async fn treasury_utxos(&self) -> Result<Vec<TreasuryUtxo>, sqlx::Error> {
        sqlx::query(
            "SELECT txid, output_index, amount FROM treasury_utxos \
             ORDER BY block_height, txid, output_index",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| {
            Ok(TreasuryUtxo {
                txid: decode_hash(row.try_get("txid")?)?,
                output_index: u32::try_from(row.try_get::<i64, _>("output_index")?)
                    .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
                amount: decode_u64(row.try_get("amount")?)?,
            })
        })
        .collect()
    }

    pub async fn exchange_request(
        &self,
        xonly_pubkey: [u8; 32],
    ) -> Result<Option<DropletExchangeRequest>, sqlx::Error> {
        sqlx::query(
            "SELECT xonly_pubkey, pset, signing_hash, requested_at_block, status, \
             completed_txid, last_error FROM droplet_exchange_requests WHERE xonly_pubkey = $1",
        )
        .bind(xonly_pubkey.to_vec())
        .fetch_optional(&self.pool)
        .await?
        .map(decode_exchange_request)
        .transpose()
    }

    pub async fn exchange_history(
        &self,
        xonly_pubkey: [u8; 32],
    ) -> Result<Vec<DropletExchangeRequest>, sqlx::Error> {
        sqlx::query(
            "SELECT xonly_pubkey, pset, signing_hash, requested_at_block, status, \
             completed_txid, last_error FROM droplet_exchange_request_history \
             WHERE xonly_pubkey = $1 ORDER BY requested_at_block DESC, signing_hash DESC \
             LIMIT 100",
        )
        .bind(xonly_pubkey.to_vec())
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(decode_exchange_request)
        .collect()
    }

    pub async fn queue_exchange(
        &self,
        xonly_pubkey: [u8; 32],
        transaction: &[u8],
        signing_hash: [u8; 32],
        block_height: u64,
    ) -> Result<(), sqlx::Error> {
        let mut db_transaction = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO droplet_exchange_request_history \
             (xonly_pubkey, pset, signing_hash, requested_at_block, status, completed_txid, last_error) \
             SELECT xonly_pubkey, pset, signing_hash, requested_at_block, status, completed_txid, last_error \
             FROM droplet_exchange_requests WHERE xonly_pubkey = $1 \
             ON CONFLICT (xonly_pubkey, requested_at_block, signing_hash) DO NOTHING",
        )
        .bind(xonly_pubkey.to_vec())
        .execute(&mut *db_transaction)
        .await?;
        sqlx::query(
            "INSERT INTO droplet_exchange_requests \
             (xonly_pubkey, pset, signing_hash, requested_at_block, status) \
             VALUES ($1, $2, $3, $4, 'pending') \
             ON CONFLICT (xonly_pubkey) DO UPDATE SET pset = excluded.pset, \
             signing_hash = excluded.signing_hash, requested_at_block = excluded.requested_at_block, \
             status = 'pending', completed_txid = NULL, last_error = NULL",
        )
        .bind(xonly_pubkey.to_vec())
        .bind(transaction)
        .bind(signing_hash.to_vec())
        .bind(encode_u64(block_height)?)
        .execute(&mut *db_transaction)
        .await?;
        db_transaction.commit().await?;
        Ok(())
    }

    pub async fn complete_exchange_request(
        &self,
        request: &DropletExchangeRequest,
        txid: [u8; 32],
    ) -> Result<bool, sqlx::Error> {
        self.finish_exchange_request(request, "completed", Some(txid), None)
            .await
    }

    pub async fn fail_exchange_request(
        &self,
        request: &DropletExchangeRequest,
        error: &str,
    ) -> Result<bool, sqlx::Error> {
        self.finish_exchange_request(request, "failed", None, Some(error))
            .await
    }

    async fn finish_exchange_request(
        &self,
        request: &DropletExchangeRequest,
        status: &str,
        txid: Option<[u8; 32]>,
        error: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let updated = sqlx::query(
            "UPDATE droplet_exchange_requests SET status = $1, completed_txid = $2, \
             last_error = $3 WHERE xonly_pubkey = $4 AND status = 'pending' \
             AND pset = $5 AND signing_hash = $6",
        )
        .bind(status)
        .bind(txid.map(|txid| txid.to_vec()))
        .bind(error)
        .bind(request.xonly_pubkey.to_vec())
        .bind(&request.transaction)
        .bind(request.signing_hash.to_vec())
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(updated == 1)
    }

    pub async fn lock_exchange(
        &self,
        xonly_pubkey: [u8; 32],
        amount: u64,
        block_height: u64,
        transaction: &[u8],
    ) -> Result<bool, sqlx::Error> {
        let updated = sqlx::query(
            "UPDATE droplets SET block_height = $1, exchange_locked = 1, last_tx = $2, \
                    exchange_amount = $4 \
               WHERE xonly_pubkey = $3 AND amount >= $4 \
                    AND (exchange_locked = 0 OR (last_tx = $2 AND exchange_amount = $4))",
        )
        .bind(encode_u64(block_height)?)
        .bind(transaction)
        .bind(xonly_pubkey.to_vec())
        .bind(encode_u64(amount)?)
        .execute(&self.pool)
        .await?
        .rows_affected();

        Ok(updated == 1)
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
        treasury_transactions: &[TreasuryTransaction],
        members: &[[u8; 32]],
    ) -> Result<(), DropletError> {
        let mut transaction = self.pool.begin().await?;
        Self::apply_block_in(&mut transaction, block, treasury_transactions, members).await?;
        MonitoredUtxoStore::record_cursor(&mut transaction, rule_set, block).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub(crate) async fn apply_block_in(
        transaction: &mut Transaction<'_, Any>,
        block: &IndexedBlock,
        treasury_transactions: &[TreasuryTransaction],
        members: &[[u8; 32]],
    ) -> Result<(), DropletError> {
        if members.is_empty() {
            return Err(DropletError::Invalid("network has no members".into()));
        }
        let mut members = members.to_vec();
        members.sort_unstable();
        members.dedup();

        for treasury_transaction in treasury_transactions {
            let mut spent_amount = 0u64;
            for (txid, output_index) in &treasury_transaction.inputs {
                let row = sqlx::query(
                    "SELECT amount FROM treasury_utxos WHERE txid = $1 AND output_index = $2",
                )
                .bind(txid.to_vec())
                .bind(i64::from(*output_index))
                .fetch_optional(&mut **transaction)
                .await?;
                if let Some(row) = row {
                    spent_amount = spent_amount
                        .checked_add(decode_u64(row.try_get("amount")?)?)
                        .ok_or_else(|| DropletError::Invalid("Treasury input overflow".into()))?;
                    sqlx::query("DELETE FROM treasury_utxos WHERE txid = $1 AND output_index = $2")
                        .bind(txid.to_vec())
                        .bind(i64::from(*output_index))
                        .execute(&mut **transaction)
                        .await?;
                }
            }

            let output_amount = treasury_transaction
                .outputs
                .iter()
                .try_fold(0u64, |total, (_, amount)| total.checked_add(*amount))
                .ok_or_else(|| DropletError::Invalid("Treasury output overflow".into()))?;
            for (output_index, amount) in &treasury_transaction.outputs {
                sqlx::query(
                    "INSERT INTO treasury_utxos (txid, output_index, amount, block_height) \
                     VALUES ($1, $2, $3, $4)",
                )
                .bind(treasury_transaction.txid.to_vec())
                .bind(i64::from(*output_index))
                .bind(encode_u64(*amount)?)
                .bind(encode_u64(block.height)?)
                .execute(&mut **transaction)
                .await?;
            }

            if spent_amount == 0 {
                credit_deposit(
                    transaction,
                    &members,
                    treasury_transaction.deposit_member,
                    output_amount,
                    block.height,
                )
                .await?;
                continue;
            }

            let member = treasury_transaction.exchange_member.ok_or_else(|| {
                DropletError::Invalid("Treasury spend has no member marker".into())
            })?;
            if !members.contains(&member) {
                return Err(DropletError::Invalid(
                    "Treasury spend identifies a non-member".into(),
                ));
            }
            let exchanged = spent_amount.checked_sub(output_amount).ok_or_else(|| {
                DropletError::Invalid("Treasury spend increases Treasury value".into())
            })?;
            let balance =
                sqlx::query("SELECT amount, deficit FROM droplets WHERE xonly_pubkey = $1")
                    .bind(member.to_vec())
                    .fetch_optional(&mut **transaction)
                    .await?
                    .map(|row| {
                        Ok::<_, sqlx::Error>((
                            decode_u64(row.try_get("amount")?)?,
                            decode_u64(row.try_get("deficit")?)?,
                        ))
                    })
                    .transpose()?;
            let (amount, deficit) = balance.unwrap_or((0, 0));
            // The spend is final on chain, so the ledger records any overdraw instead of failing.
            let shortfall = exchanged.saturating_sub(amount);
            let deficit = deficit
                .checked_add(shortfall)
                .ok_or_else(|| DropletError::Invalid("Droplets deficit overflow".into()))?;
            if shortfall > 0 {
                tracing::warn!(
                    member = %hex::encode(member),
                    txid = %hex::encode(treasury_transaction.txid),
                    shortfall,
                    "Treasury spend exceeds the member Droplets balance; recorded a deficit"
                );
            }
            sqlx::query(
                "INSERT INTO droplets (xonly_pubkey, amount, block_height, deficit) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (xonly_pubkey) DO UPDATE SET amount = excluded.amount, \
                 block_height = excluded.block_height, deficit = excluded.deficit, \
                 exchange_locked = 0, last_tx = NULL, exchange_amount = 0",
            )
            .bind(member.to_vec())
            .bind(encode_u64(amount.saturating_sub(exchanged))?)
            .bind(encode_u64(block.height)?)
            .bind(encode_u64(deficit)?)
            .execute(&mut **transaction)
            .await?;
        }

        Ok(())
    }

    pub async fn unlock_exchange(
        &self,
        xonly_pubkey: [u8; 32],
        block_height: u64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE droplets SET block_height = $1, exchange_locked = 0, last_tx = NULL, \
             exchange_amount = 0 \
             WHERE xonly_pubkey = $2",
        )
        .bind(encode_u64(block_height)?)
        .bind(xonly_pubkey.to_vec())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_locked_transaction(
        &self,
        xonly_pubkey: [u8; 32],
        expected_transaction: &[u8],
        transaction: &[u8],
    ) -> Result<bool, sqlx::Error> {
        let updated = sqlx::query(
            "UPDATE droplets SET last_tx = $1 WHERE xonly_pubkey = $2 \
             AND exchange_locked = 1 AND last_tx = $3",
        )
        .bind(transaction)
        .bind(xonly_pubkey.to_vec())
        .bind(expected_transaction)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(updated == 1)
    }
}

async fn credit_deposit(
    transaction: &mut sqlx::Transaction<'_, sqlx::Any>,
    members: &[[u8; 32]],
    tagged_member: Option<[u8; 32]>,
    amount: u64,
    block_height: u64,
) -> Result<(), DropletError> {
    if amount == 0 {
        return Ok(());
    }
    let allocations = if let Some(member) = tagged_member.filter(|member| members.contains(member))
    {
        vec![(member, amount)]
    } else {
        let member_count = u64::try_from(members.len())
            .map_err(|_| DropletError::Invalid("member count overflow".into()))?;
        let share = amount / member_count;
        let remainder = amount % member_count;
        members
            .iter()
            .enumerate()
            .map(|(index, member)| {
                let remainder_share = u64::from(index < remainder as usize);
                (*member, share + remainder_share)
            })
            .collect()
    };

    for (member, amount) in allocations {
        sqlx::query(CREDIT_SQL)
            .bind(member.to_vec())
            .bind(encode_u64(amount)?)
            .bind(encode_u64(block_height)?)
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}

fn decode_balance(row: sqlx::any::AnyRow) -> Result<DropletBalance, sqlx::Error> {
    Ok(DropletBalance {
        xonly_pubkey: row
            .try_get::<Vec<u8>, _>("xonly_pubkey")?
            .try_into()
            .map_err(|_| sqlx::Error::Decode("invalid x-only public key length".into()))?,
        amount: decode_u64(row.try_get("amount")?)?,
        block_height: decode_u64(row.try_get("block_height")?)?,
        exchange_locked: row.try_get::<i64, _>("exchange_locked")? != 0,
        last_tx: row.try_get("last_tx")?,
    })
}

fn decode_exchange_request(row: sqlx::any::AnyRow) -> Result<DropletExchangeRequest, sqlx::Error> {
    Ok(DropletExchangeRequest {
        xonly_pubkey: decode_hash(row.try_get("xonly_pubkey")?)?,
        transaction: row.try_get("pset")?,
        signing_hash: decode_hash(row.try_get("signing_hash")?)?,
        requested_at_block: decode_u64(row.try_get("requested_at_block")?)?,
        status: row.try_get("status")?,
        completed_txid: row
            .try_get::<Option<Vec<u8>>, _>("completed_txid")?
            .map(decode_hash)
            .transpose()?,
        last_error: row.try_get("last_error")?,
    })
}

#[cfg(test)]
mod tests;
