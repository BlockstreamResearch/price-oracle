use std::env;

use contracts::artifacts::account::{AccountProgram, derived_account::AccountArguments};
use secp256k1::{Keypair, SecretKey, schnorr};
use serde::Serialize;
use sha2::{Digest, Sha256};
use simplex::provider::SimplicityNetwork;

const USER_REQUEST_TAG: &str = "OracleNetworkV1/NetworkUserRequests";
const DEVELOPMENT_USER_KEY: [u8; 32] = [31; 32];

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let storm_eye_asset = arguments
        .next()
        .ok_or("usage: live_tick_request STORM_EYE_ASSET_ID [FEE_TXID:VOUT]")?;
    let storm_eye_asset: [u8; 32] = hex::decode(storm_eye_asset)?
        .try_into()
        .map_err(|_| "Storm Eye asset ID must be 32 bytes")?;
    let secret_key = SecretKey::from_secret_bytes(DEVELOPMENT_USER_KEY)?;
    let keypair = Keypair::from_secret_key(&secret_key);
    let public_key = keypair.x_only_public_key().0.serialize();
    let account = AccountProgram::new(&AccountArguments {
        storm_eye_asset_id: storm_eye_asset,
        account_owner_pubkey: public_key,
    });
    let address = account
        .as_ref()
        .get_tr_address(&SimplicityNetwork::default_regtest());

    let Some(fee_utxo) = arguments.next() else {
        println!("{address}");
        return Ok(());
    };
    if arguments.next().is_some() {
        return Err("expected at most one fee UTXO".into());
    }

    let payload = serde_json::json!({
        "utxo_auth_method": {
            "kind": "signature-auth",
            "auth_data": hex::encode(public_key),
        }
    })
    .to_string();
    let mut request = NetworkUserRequests {
        header: UserRequestHeader {
            signature: String::new(),
            public_key: hex::encode(public_key),
            fee_utxos: vec![fee_utxo],
        },
        requests: vec![UserRequest {
            kind: "tick-utxo".into(),
            payload,
        }],
    };
    request.header.signature =
        hex::encode(schnorr::sign(&signing_hash(&request), &keypair).to_byte_array());

    println!("{}", serde_json::to_string(&request)?);
    Ok(())
}

fn signing_hash(request: &NetworkUserRequests) -> [u8; 32] {
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
