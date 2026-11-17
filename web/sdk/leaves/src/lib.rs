//! The Account and voucher leaf hashes the browser SDK pins, compiled from the
//! contract sources the nodes compile, by the compiler they compile them with.
//!
//! One request line in, one answer out, both through a shared buffer:
//!
//! ```text
//! account <storm eye asset id> <owner x-only key>
//! voucher <storm eye asset id> signature <x-only key>
//! voucher <storm eye asset id> script <SHA-256 of the script>
//! voucher <storm eye asset id> asset <asset id>
//! ```
//!
//! The answer is `ok <32-byte hex leaf>` or `error <reason>`.

use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::str::FromStr;

use simplicityhl::ast::ElementsJetHinter;
use simplicityhl::elements::taproot::TapLeafHash;
use simplicityhl::elements::{AssetId, Script};
use simplicityhl::num::U256;
use simplicityhl::simplicity::leaf_version;
use simplicityhl::value::UIntValue;
use simplicityhl::{
    Arguments, CompiledProgram, TemplateProgramWitness, UnstableFeatures, Value,
    WitnessNameToValueMap,
};

/// What `simplex build` writes, and the contracts crate embeds.
pub const ACCOUNT_SOURCE: &str =
    include_str!("../../../../contracts/src/artifacts/simf/account.simf");
pub const VOUCHER_SOURCE: &str =
    include_str!("../../../../contracts/src/artifacts/simf/voucher.simf");

/// How a voucher's burn is authorized, as the contracts crate names it.
#[derive(Clone, Copy, Debug)]
pub enum AuthMethod {
    Asset(AssetId),
    ScriptHash([u8; 32]),
    Signature([u8; 32]),
}

const CAPACITY: usize = 512;

struct Buffer(UnsafeCell<[u8; CAPACITY]>);

// The module is single-threaded: one caller writes, calls and reads in turn.
unsafe impl Sync for Buffer {}

static BUFFER: Buffer = Buffer(UnsafeCell::new([0; CAPACITY]));

/// Where the caller writes a request and reads its answer.
#[unsafe(no_mangle)]
pub extern "C" fn leaves_buffer() -> *mut u8 {
    BUFFER.0.get().cast()
}

/// Answers the `length`-byte request in the buffer; returns the answer's length.
#[unsafe(no_mangle)]
pub extern "C" fn leaves_derive(length: usize) -> usize {
    // SAFETY: the buffer is only touched between calls, by the one caller.
    let buffer = unsafe { &mut *BUFFER.0.get() };
    let answer = match buffer
        .get(..length)
        .ok_or_else(|| "request is longer than the buffer".to_string())
        .and_then(|request| std::str::from_utf8(request).map_err(|error| error.to_string()))
        .and_then(derive)
    {
        Ok(leaf) => format!("ok {}", hex::encode(leaf)),
        Err(reason) => format!("error {reason}"),
    };
    let answer = &answer.as_bytes()[..answer.len().min(CAPACITY)];
    buffer[..answer.len()].copy_from_slice(answer);
    answer.len()
}

/// The leaf a request names.
pub fn derive(request: &str) -> Result<[u8; 32], String> {
    let fields: Vec<&str> = request.split(' ').collect();
    match fields.as_slice() {
        ["account", storm_eye, owner] => account_leaf(asset(storm_eye)?, bytes(owner)?),
        ["voucher", storm_eye, method, data] => {
            let auth_method = match *method {
                "signature" => AuthMethod::Signature(bytes(data)?),
                "script" => AuthMethod::ScriptHash(bytes(data)?),
                "asset" => AuthMethod::Asset(asset(data)?),
                _ => return Err(format!("unknown authentication method '{method}'")),
            };
            voucher_leaf(asset(storm_eye)?, auth_method)
        }
        _ => Err("unknown request".to_string()),
    }
}

/// The Account of `owner`, as `AccountProgram::new` compiles it.
pub fn account_leaf(storm_eye_asset_id: AssetId, owner: [u8; 32]) -> Result<[u8; 32], String> {
    leaf(
        ACCOUNT_SOURCE,
        [
            (
                "STORM_EYE_ASSET_ID",
                u256(storm_eye_asset_id.to_byte_array()),
            ),
            ("ACCOUNT_OWNER_PUBKEY", u256(owner)),
        ],
    )
}

/// A Tick or Verifier, as `Voucher::new` compiles it: the method's own
/// argument is set and the other two are zero.
pub fn voucher_leaf(
    storm_eye_asset_id: AssetId,
    auth_method: AuthMethod,
) -> Result<[u8; 32], String> {
    let (method, asset_id, script_hash, pubkey) = match auth_method {
        AuthMethod::Asset(asset_id) => (0, asset_id.to_byte_array(), [0; 32], [0; 32]),
        AuthMethod::ScriptHash(script_hash) => (1, [0; 32], script_hash, [0; 32]),
        AuthMethod::Signature(pubkey) => (2, [0; 32], [0; 32], pubkey),
    };
    leaf(
        VOUCHER_SOURCE,
        [
            (
                "STORM_EYE_ASSET_ID",
                u256(storm_eye_asset_id.to_byte_array()),
            ),
            ("AUTH_METHOD", Value::from(UIntValue::U32(method))),
            ("AUTH_ASSET_ID", u256(asset_id)),
            ("AUTH_SCRIPT_HASH", u256(script_hash)),
            ("AUTH_PUBKEY", u256(pubkey)),
        ],
    )
}

/// Compiled as the Simplex `Program` compiles: every unstable feature on,
/// no debug symbols, and the leaf is the program's commitment root.
fn leaf<const N: usize>(
    source: &'static str,
    arguments: [(&'static str, Value); N],
) -> Result<[u8; 32], String> {
    let arguments =
        Arguments::from_map(HashMap::from(arguments.map(|(name, value)| {
            (TemplateProgramWitness::parameter_from_str(name), value)
        })));
    let compiled = CompiledProgram::new_with_unstable(
        source,
        &UnstableFeatures::all(),
        arguments,
        false,
        Box::new(ElementsJetHinter),
    )?;
    let script = Script::from(compiled.commit().cmr().as_ref().to_vec());

    Ok(TapLeafHash::from_script(&script, leaf_version()).to_byte_array())
}

fn u256(bytes: [u8; 32]) -> Value {
    Value::from(UIntValue::U256(U256::from_byte_array(bytes)))
}

fn asset(encoded: &str) -> Result<AssetId, String> {
    AssetId::from_str(encoded).map_err(|error| format!("invalid asset id: {error}"))
}

fn bytes(encoded: &str) -> Result<[u8; 32], String> {
    hex::decode(encoded)
        .ok()
        .and_then(|decoded| decoded.try_into().ok())
        .ok_or_else(|| "expected 32-byte hex".to_string())
}

#[cfg(test)]
mod tests {
    use contracts::artifacts::account::{AccountProgram, derived_account::AccountArguments};
    use contracts::artifacts::voucher::VoucherProgram;
    use contracts::voucher::{Voucher, VoucherAuthMethod, VoucherParameters};
    use simplex::provider::SimplicityNetwork;

    use super::*;

    const STORM_EYE: &str = "25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a";
    const OWNER: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    /// Distinct, unstructured 32-byte values.
    fn sample(seed: u8) -> [u8; 32] {
        std::array::from_fn(|index| seed.wrapping_mul(31).wrapping_add(index as u8 * 7))
    }

    fn contract_voucher(storm_eye: AssetId, auth_method: VoucherAuthMethod) -> [u8; 32] {
        Voucher::new(VoucherParameters {
            storm_eye_asset_id: storm_eye,
            auth_method,
            network: SimplicityNetwork::default_regtest(),
        })
        .get_tapleaf_hash()
    }

    #[test]
    fn compiles_the_sources_the_contracts_crate_embeds() {
        assert_eq!(ACCOUNT_SOURCE, AccountProgram::SOURCE);
        assert_eq!(VOUCHER_SOURCE, VoucherProgram::SOURCE);
    }

    #[test]
    fn compiles_every_leaf_the_contracts_crate_compiles() {
        for seed in 1..=4 {
            let storm_eye = AssetId::from_byte_array(sample(seed));
            let data = sample(seed + 100);

            assert_eq!(
                account_leaf(storm_eye, data).unwrap(),
                AccountProgram::new(&AccountArguments {
                    storm_eye_asset_id: storm_eye.to_byte_array(),
                    account_owner_pubkey: data,
                })
                .get_tapleaf_hash(),
            );
            assert_eq!(
                voucher_leaf(storm_eye, AuthMethod::Signature(data)).unwrap(),
                contract_voucher(
                    storm_eye,
                    VoucherAuthMethod::Signature { auth_pubkey: data }
                ),
            );
            assert_eq!(
                voucher_leaf(storm_eye, AuthMethod::ScriptHash(data)).unwrap(),
                contract_voucher(
                    storm_eye,
                    VoucherAuthMethod::Script {
                        auth_script_hash: data
                    }
                ),
            );
            let auth_asset = AssetId::from_byte_array(data);
            assert_eq!(
                voucher_leaf(storm_eye, AuthMethod::Asset(auth_asset)).unwrap(),
                contract_voucher(
                    storm_eye,
                    VoucherAuthMethod::Asset {
                        auth_asset_id: auth_asset
                    }
                ),
            );
        }
    }

    #[test]
    fn reads_an_asset_id_as_the_node_prints_it() {
        let storm_eye = AssetId::from_str(STORM_EYE).unwrap();
        let owner = bytes(OWNER).unwrap();

        assert_eq!(
            derive(&format!("account {STORM_EYE} {OWNER}")).unwrap(),
            account_leaf(storm_eye, owner).unwrap(),
        );
        assert_eq!(
            derive(&format!("voucher {STORM_EYE} signature {OWNER}")).unwrap(),
            voucher_leaf(storm_eye, AuthMethod::Signature(owner)).unwrap(),
        );
        assert_eq!(
            derive(&format!("voucher {STORM_EYE} script {OWNER}")).unwrap(),
            voucher_leaf(storm_eye, AuthMethod::ScriptHash(owner)).unwrap(),
        );
        assert_eq!(
            derive(&format!("voucher {STORM_EYE} asset {STORM_EYE}")).unwrap(),
            voucher_leaf(storm_eye, AuthMethod::Asset(storm_eye)).unwrap(),
        );
    }

    #[test]
    fn refuses_a_malformed_request() {
        assert!(derive("account").is_err());
        assert!(derive(&format!("account {STORM_EYE} 00")).is_err());
        assert!(derive(&format!("account not-an-asset {OWNER}")).is_err());
        assert!(derive(&format!("voucher {STORM_EYE} password {OWNER}")).is_err());
    }

    #[test]
    fn answers_through_the_buffer() {
        let request = format!("account {STORM_EYE} {OWNER}");
        let expected = format!("ok {}", hex::encode(derive(&request).unwrap()));
        // SAFETY: this is the only test touching the buffer.
        let buffer = unsafe { std::slice::from_raw_parts_mut(leaves_buffer(), CAPACITY) };
        buffer[..request.len()].copy_from_slice(request.as_bytes());
        let length = leaves_derive(request.len());
        assert_eq!(&buffer[..length], expected.as_bytes());

        buffer[..7].copy_from_slice(b"nothing");
        let length = leaves_derive(7);
        assert_eq!(&buffer[..length], b"error unknown request");
    }
}
