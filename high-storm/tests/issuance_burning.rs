use std::{error::Error, str::FromStr, time::Duration};

use bitcoin::{Amount, Denomination};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use contracts::artifacts::account::{AccountProgram, derived_account::AccountArguments};
use high_storm::{
    config::Config,
    db::{Database, network_asset::STORM_EYE_KIND},
};
use secp256k1::{Keypair, SecretKey, schnorr};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value, json};
use sha2::{Digest, Sha256};
use simplex::{
    provider::SimplicityNetwork,
    simplicityhl::{
        elements::{AssetId, Block, BlockHash, Script, Transaction, Txid, encode},
        simplicity::hashes::Hash,
    },
};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, sleep},
};

const USER_REQUEST_TAG: &str = "OracleNetworkV1/NetworkUserRequests";
const TICK_LIFETIME_BLOCKS: u64 = 60;
const RPC_URL: &str = "http://127.0.0.1:18884";
const WALLET_RPC_URL: &str = "http://127.0.0.1:18884/wallet/funded-key";
const RPC_USER: &str = "high-storm";
const RPC_PASSWORD: &str = "high-storm";
const API_ADDRESS: &str = "127.0.0.1:9100";
const ACCOUNT_FUNDING_SATS: u64 = 10_000;
const FUNDING_FEE_SATS: u64 = 1_000;
const BURN_FEE_SATS: u64 = 500;

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Serialize)]
struct NetworkUserRequests {
    header: UserRequestHeader,
    requests: Vec<UserRequest>,
}

#[derive(Serialize)]
struct UserRequestHeader {
    signature: String,
    public_key: String,
    fee_utxos: Vec<String>,
}

#[derive(Serialize)]
struct UserRequest {
    kind: String,
    payload: String,
}

#[derive(Deserialize)]
struct CreatedRequest {
    request_hash: String,
}

#[derive(Deserialize)]
struct RequestStatus {
    status: String,
}

#[derive(Deserialize)]
struct WalletUtxo {
    txid: String,
    vout: u32,
    address: String,
    amount: Number,
    asset: String,
}

#[derive(Deserialize)]
struct SignedTransaction {
    hex: String,
    complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IndexedTick {
    output_index: u32,
    amount: u64,
    owner: [u8; 32],
    reserve_output_index: u32,
    status: String,
    burn_txid: Option<[u8; 32]>,
}

#[test]
fn burning_time_is_sixty_blocks_for_production_and_docker() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let production = Config::from_file(manifest.join("config.example.toml")).unwrap();
    assert_eq!(
        production.service.user_requests.tick_lifetime_blocks,
        TICK_LIFETIME_BLOCKS
    );

    for node in ["node-1.toml", "node-2.toml", "node-3.toml"] {
        let config = Config::from_file(manifest.join("docker").join(node)).unwrap();
        assert_eq!(
            config.service.user_requests.tick_lifetime_blocks, TICK_LIFETIME_BLOCKS,
            "{node} must expire Ticks after 60 blocks"
        );
    }
}

#[tokio::test]
#[ignore = "requires the bundled three-node Docker Compose stack"]
async fn batches_two_users_and_burns_both_to_one_empty_op_return() -> TestResult<()> {
    let rpc = rpc_client(RPC_URL)?;
    let wallet = rpc_client(WALLET_RPC_URL)?;
    let databases = database_pools().await?;
    let asset_database = Database::connect(
        "postgres://high-storm:high-storm@127.0.0.1:5432/high-storm-node-1",
        1,
    )
    .await?;
    let storm_eye = asset_database
        .network_assets()
        .get(STORM_EYE_KIND)
        .await?
        .expect("Storm Eye must be initialized");
    let network = elements_network(&rpc)?;
    let policy_asset = network.policy_asset();

    let users = [
        user(31, storm_eye.asset_id, &network)?,
        user(32, storm_eye.asset_id, &network)?,
    ];
    let (funding_txid, mining_address) = fund_accounts(
        &rpc,
        &wallet,
        policy_asset,
        [&users[0].address, &users[1].address],
    )
    .await?;
    mine_blocks(&rpc, 1, &mining_address)?;

    let mut request_hashes = Vec::new();
    for (vout, user) in users.iter().enumerate() {
        let request =
            signed_tick_request(&user.keypair, user.owner, &format!("{funding_txid}:{vout}"));
        let (status, body) = http_json("POST", "/users/requests", Some(&request)).await?;
        assert_eq!(status, 201, "request submission failed: {body}");
        request_hashes.push(serde_json::from_value::<CreatedRequest>(body)?.request_hash);
    }

    let issuance_txid = wait_for_spender(&rpc, &funding_txid, 0, Duration::from_secs(45)).await?;
    let issuance = raw_transaction(&rpc, &issuance_txid)?;
    assert!(spends(&issuance, &funding_txid, 0));
    assert!(spends(&issuance, &funding_txid, 1));
    assert_eq!(
        issuance
            .input
            .iter()
            .filter(|input| input.previous_output.txid.to_string() == funding_txid)
            .count(),
        2,
        "both users must be handled by one issuance transaction"
    );

    if transaction_height(&rpc, &issuance_txid)?.is_none() {
        mine_blocks(&rpc, 1, &mining_address)?;
    }
    let issuance_height = wait_for_confirmation(&rpc, &issuance_txid).await?;
    let issuance_txid = issuance.txid();
    let mut expected_owners = users.iter().map(|user| user.owner).collect::<Vec<_>>();
    expected_owners.sort_unstable();
    let active = wait_for_all_ticks(
        &databases,
        issuance_txid,
        "active",
        2,
        Duration::from_secs(60),
    )
    .await?;
    assert!(active.windows(2).all(|rows| rows[0] == rows[1]));
    let mut indexed_owners = active[0].iter().map(|tick| tick.owner).collect::<Vec<_>>();
    indexed_owners.sort_unstable();
    assert_eq!(indexed_owners, expected_owners);
    for request_hash in request_hashes {
        wait_for_request_status(&request_hash, "executed").await?;
    }

    let expiry_height = issuance_height + TICK_LIFETIME_BLOCKS;
    let tip: u64 = rpc.call("getblockcount", &[])?;
    mine_blocks(&rpc, expiry_height.saturating_sub(tip), &mining_address)?;

    let burn_txid =
        wait_for_common_burn(&databases, issuance_txid, Duration::from_secs(120)).await?;
    let burn = wait_for_raw_transaction(&rpc, &burn_txid, Duration::from_secs(30)).await?;
    for tick in &active[0] {
        assert!(burn.input.iter().any(|input| {
            input.previous_output.txid == issuance_txid
                && input.previous_output.vout == tick.output_index
        }));
        assert!(burn.input.iter().any(|input| {
            input.previous_output.txid == issuance_txid
                && input.previous_output.vout == tick.reserve_output_index
        }));
    }

    let burn_outputs = burn
        .output
        .iter()
        .filter(|output| output.script_pubkey == Script::new_op_return(&[]))
        .collect::<Vec<_>>();
    assert_eq!(burn_outputs.len(), 1, "burn must have one OP_RETURN output");
    assert_eq!(
        burn_outputs[0].value.explicit(),
        Some(active[0].iter().map(|tick| tick.amount).sum())
    );
    assert!(burn.output.iter().any(|output| {
        output.asset.explicit() == Some(policy_asset)
            && output.value.explicit() == Some(BURN_FEE_SATS)
            && output.script_pubkey.is_empty()
    }));
    for tick in &active[0] {
        let user = users
            .iter()
            .find(|user| user.owner == tick.owner)
            .expect("every indexed owner came from this test");
        let reserve = issuance.output[tick.reserve_output_index as usize]
            .value
            .explicit()
            .expect("burn reserves are explicit");
        assert!(burn.output.iter().any(|output| {
            output.asset.explicit() == Some(policy_asset)
                && output.value.explicit() == Some(reserve - BURN_FEE_SATS / 2)
                && output.script_pubkey == user.script
        }));
    }

    if transaction_height(&rpc, &burn_txid)?.is_none() {
        mine_blocks(&rpc, 1, &mining_address)?;
    }
    wait_for_confirmation(&rpc, &burn_txid).await?;
    wait_for_no_ticks(&databases, issuance_txid, Duration::from_secs(60)).await?;

    Ok(())
}

struct TestUser {
    keypair: Keypair,
    owner: [u8; 32],
    script: simplex::simplicityhl::elements::Script,
    address: String,
}

fn user(key_byte: u8, storm_eye: [u8; 32], network: &SimplicityNetwork) -> TestResult<TestUser> {
    let keypair = Keypair::from_secret_key(&SecretKey::from_secret_bytes([key_byte; 32])?);
    let owner = keypair.x_only_public_key().0.serialize();
    let account = AccountProgram::new(&AccountArguments {
        storm_eye_asset_id: storm_eye,
        account_owner_pubkey: owner,
    });
    Ok(TestUser {
        keypair,
        owner,
        script: account.get_script_pubkey(network),
        address: account.as_ref().get_tr_address(network).to_string(),
    })
}

fn rpc_client(url: &str) -> TestResult<Client> {
    Ok(Client::new(
        url,
        Auth::UserPass(RPC_USER.to_string(), RPC_PASSWORD.to_string()),
    )?)
}

fn elements_network(rpc: &Client) -> TestResult<SimplicityNetwork> {
    let sidechain: Value = rpc.call("getsidechaininfo", &[])?;
    let genesis_hash: String = rpc.call("getblockhash", &[0.into()])?;
    Ok(SimplicityNetwork::ElementsCustom {
        policy_asset: AssetId::from_str(
            sidechain["pegged_asset"]
                .as_str()
                .ok_or("missing policy asset")?,
        )?,
        genesis_hash: BlockHash::from_str(&genesis_hash)?,
    })
}

async fn fund_accounts(
    rpc: &Client,
    wallet: &Client,
    policy_asset: AssetId,
    addresses: [&str; 2],
) -> TestResult<(String, String)> {
    let deadline = Instant::now() + Duration::from_secs(75);
    let source = loop {
        let utxos: Vec<WalletUtxo> = wallet.call("listunspent", &[1.into(), 9_999_999.into()])?;
        if let Some(source) = utxos.into_iter().find(|utxo| {
            utxo.asset == policy_asset.to_string()
                && coin_to_sats(&utxo.amount)
                    .is_ok_and(|amount| amount > ACCOUNT_FUNDING_SATS * 2 + FUNDING_FEE_SATS)
        }) {
            break source;
        }
        if Instant::now() >= deadline {
            return Err("funded wallet has no suitable confirmed policy-asset UTXO".into());
        }
        sleep(Duration::from_millis(250)).await;
    };
    let source_amount = coin_to_sats(&source.amount)?;
    let outputs = Value::Array(vec![
        amount_output(addresses[0], ACCOUNT_FUNDING_SATS),
        amount_output(addresses[1], ACCOUNT_FUNDING_SATS),
        amount_output(
            &source.address,
            source_amount - ACCOUNT_FUNDING_SATS * 2 - FUNDING_FEE_SATS,
        ),
        amount_output("fee", FUNDING_FEE_SATS),
    ]);
    let raw: String = rpc.call(
        "createrawtransaction",
        &[json!([{"txid": source.txid, "vout": source.vout}]), outputs],
    )?;
    let signed: SignedTransaction = wallet.call("signrawtransactionwithwallet", &[raw.into()])?;
    assert!(signed.complete);
    Ok((
        rpc.call("sendrawtransaction", &[signed.hex.into()])?,
        source.address,
    ))
}

fn signed_tick_request(keypair: &Keypair, owner: [u8; 32], fee_utxo: &str) -> NetworkUserRequests {
    let mut request = NetworkUserRequests {
        header: UserRequestHeader {
            signature: String::new(),
            public_key: hex::encode(owner),
            fee_utxos: vec![fee_utxo.to_string()],
        },
        requests: vec![UserRequest {
            kind: "tick-utxo".to_string(),
            payload: json!({
                "utxo_auth_method": {
                    "kind": "signature-auth",
                    "auth_data": hex::encode(owner),
                }
            })
            .to_string(),
        }],
    };
    request.header.signature =
        hex::encode(schnorr::sign(&request_signing_hash(&request), keypair).to_byte_array());
    request
}

fn request_signing_hash(request: &NetworkUserRequests) -> [u8; 32] {
    let mut message = Vec::new();
    for request in &request.requests {
        message.extend_from_slice(request.payload.as_bytes());
    }
    for fee_utxo in &request.header.fee_utxos {
        message.extend_from_slice(fee_utxo.as_bytes());
    }
    let tag_hash = Sha256::digest(USER_REQUEST_TAG.as_bytes());
    let mut hash = Sha256::new();
    hash.update(tag_hash);
    hash.update(tag_hash);
    hash.update(message);
    hash.finalize().into()
}

async fn http_json<T: Serialize>(
    method: &str,
    path: &str,
    body: Option<&T>,
) -> TestResult<(u16, Value)> {
    let body = body
        .map(serde_json::to_vec)
        .transpose()?
        .unwrap_or_default();
    let mut stream = TcpStream::connect(API_ADDRESS).await?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {API_ADDRESS}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(&body).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let separator = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or("invalid HTTP response")?;
    let status = std::str::from_utf8(&response[..separator])?
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("missing HTTP status")?
        .parse()?;
    Ok((status, serde_json::from_slice(&response[separator + 4..])?))
}

async fn wait_for_request_status(request_hash: &str, expected: &str) -> TestResult<()> {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let (status, body) =
            http_json::<Value>("GET", &format!("/users/requests/{request_hash}"), None).await?;
        assert_eq!(status, 200);
        if serde_json::from_value::<RequestStatus>(body)?.status == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("request did not reach {expected}").into());
        }
        sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_for_spender(
    rpc: &Client,
    previous_txid: &str,
    previous_vout: u32,
    timeout: Duration,
) -> TestResult<String> {
    let start_height: u64 = rpc.call("getblockcount", &[])?;
    let deadline = Instant::now() + timeout;
    loop {
        let mempool: Vec<String> = rpc.call("getrawmempool", &[])?;
        for txid in mempool {
            let transaction = raw_transaction(rpc, &txid)?;
            if spends(&transaction, previous_txid, previous_vout) {
                return Ok(txid);
            }
        }
        let tip: u64 = rpc.call("getblockcount", &[])?;
        for height in start_height..=tip {
            let hash: String = rpc.call("getblockhash", &[height.into()])?;
            let encoded: String = rpc.call("getblock", &[hash.into(), 0.into()])?;
            let block: Block = encode::deserialize(&hex::decode(encoded)?)?;
            if let Some(transaction) = block
                .txdata
                .iter()
                .find(|transaction| spends(transaction, previous_txid, previous_vout))
            {
                return Ok(transaction.txid().to_string());
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for spending transaction".into());
        }
        sleep(Duration::from_millis(250)).await;
    }
}

fn spends(transaction: &Transaction, previous_txid: &str, previous_vout: u32) -> bool {
    transaction.input.iter().any(|input| {
        input.previous_output.txid.to_string() == previous_txid
            && input.previous_output.vout == previous_vout
    })
}

fn raw_transaction(rpc: &Client, txid: &str) -> TestResult<Transaction> {
    let encoded: String = rpc.call("getrawtransaction", &[txid.into(), false.into()])?;
    Ok(encode::deserialize(&hex::decode(encoded)?)?)
}

async fn wait_for_raw_transaction(
    rpc: &Client,
    txid: &str,
    timeout: Duration,
) -> TestResult<Transaction> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(transaction) = raw_transaction(rpc, txid) {
            return Ok(transaction);
        }
        if Instant::now() >= deadline {
            return Err(format!("transaction {txid} did not propagate").into());
        }
        sleep(Duration::from_millis(250)).await;
    }
}

fn transaction_height(rpc: &Client, txid: &str) -> TestResult<Option<u64>> {
    let transaction: Value = rpc.call("getrawtransaction", &[txid.into(), true.into()])?;
    let Some(block_hash) = transaction["blockhash"].as_str() else {
        return Ok(None);
    };
    let header: Value = rpc.call("getblockheader", &[block_hash.into(), true.into()])?;
    Ok(header["height"].as_u64())
}

async fn wait_for_confirmation(rpc: &Client, txid: &str) -> TestResult<u64> {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Some(height) = transaction_height(rpc, txid)? {
            return Ok(height);
        }
        if Instant::now() >= deadline {
            return Err(format!("transaction {txid} did not confirm").into());
        }
        sleep(Duration::from_millis(250)).await;
    }
}

fn mine_blocks(rpc: &Client, count: u64, address: &str) -> TestResult<()> {
    if count > 0 {
        let _: Vec<String> = rpc.call("generatetoaddress", &[count.into(), address.into()])?;
    }
    Ok(())
}

async fn database_pools() -> TestResult<Vec<PgPool>> {
    let mut pools = Vec::new();
    for database in [
        "high-storm-node-1",
        "high-storm-node-2",
        "high-storm-node-3",
    ] {
        pools.push(
            PgPoolOptions::new()
                .max_connections(1)
                .connect(&format!(
                    "postgres://high-storm:high-storm@127.0.0.1:5432/{database}"
                ))
                .await?,
        );
    }
    Ok(pools)
}

async fn indexed_ticks(pool: &PgPool, txid: Txid) -> TestResult<Vec<IndexedTick>> {
    let rows = sqlx::query(
		"SELECT output_index, amount, account_owner_pubkey, burning_fee_output_index, status, burn_txid \
		 FROM monitored_utxos WHERE txid = $1 ORDER BY output_index",
	)
	.bind(txid.to_byte_array().to_vec())
	.fetch_all(pool)
	.await?;
    rows.into_iter()
        .map(|row| {
            let owner: Vec<u8> = row.try_get("account_owner_pubkey")?;
            let burn_txid: Option<Vec<u8>> = row.try_get("burn_txid")?;
            Ok(IndexedTick {
                output_index: u32::try_from(row.try_get::<i64, _>("output_index")?)?,
                amount: u64::try_from(row.try_get::<i64, _>("amount")?)?,
                owner: owner.try_into().map_err(|_| "invalid owner length")?,
                reserve_output_index: u32::try_from(
                    row.try_get::<i64, _>("burning_fee_output_index")?,
                )?,
                status: row.try_get("status")?,
                burn_txid: burn_txid
                    .map(|txid| txid.try_into().map_err(|_| "invalid burn txid length"))
                    .transpose()?,
            })
        })
        .collect()
}

async fn wait_for_all_ticks(
    pools: &[PgPool],
    txid: Txid,
    expected_status: &str,
    expected_count: usize,
    timeout: Duration,
) -> TestResult<Vec<Vec<IndexedTick>>> {
    let deadline = Instant::now() + timeout;
    loop {
        let mut all = Vec::with_capacity(pools.len());
        for pool in pools {
            all.push(indexed_ticks(pool, txid).await?);
        }
        if all.iter().all(|ticks| {
            ticks.len() == expected_count && ticks.iter().all(|tick| tick.status == expected_status)
        }) {
            return Ok(all);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "not every node indexed {expected_count} Ticks as {expected_status}: {all:?}"
            )
            .into());
        }
        sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_for_common_burn(
    pools: &[PgPool],
    issuance_txid: Txid,
    timeout: Duration,
) -> TestResult<String> {
    let deadline = Instant::now() + timeout;
    loop {
        let mut txids = Vec::new();
        for pool in pools {
            let ticks = indexed_ticks(pool, issuance_txid).await?;
            txids.extend(ticks.into_iter().filter_map(|tick| tick.burn_txid));
        }
        if txids.len() == pools.len() * 2 && txids.windows(2).all(|pair| pair[0] == pair[1]) {
            return Ok(Txid::from_byte_array(txids[0]).to_string());
        }
        if Instant::now() >= deadline {
            return Err(format!("two users did not enter one burn transaction: {txids:?}").into());
        }
        sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_for_no_ticks(
    pools: &[PgPool],
    issuance_txid: Txid,
    timeout: Duration,
) -> TestResult<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let mut remaining = 0usize;
        for pool in pools {
            remaining += indexed_ticks(pool, issuance_txid).await?.len();
        }
        if remaining == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "confirmed Tick records were not deleted from every node: {remaining} remain"
            )
            .into());
        }
        sleep(Duration::from_millis(250)).await;
    }
}

fn coin_to_sats(value: &Number) -> TestResult<u64> {
    Ok(Amount::from_str_in(&value.to_string(), Denomination::Bitcoin)?.to_sat())
}

fn amount_output(destination: &str, sats: u64) -> Value {
    let mut output = Map::new();
    let amount = Amount::from_sat(sats).to_string_in(Denomination::Bitcoin);
    output.insert(
        destination.to_string(),
        Value::Number(Number::from_str(&amount).expect("satoshi amount is valid JSON")),
    );
    Value::Object(output)
}
