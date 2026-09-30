use contracts::artifacts::voucher::{VoucherProgram, derived_voucher::VoucherArguments};
use simplex::{
    provider::SimplicityNetwork,
    simplicityhl::elements::{Script, opcodes, schnorr::XOnlyPublicKey, script::Instruction},
    utils::hash_script,
};

use crate::external_api::users::UtxoAuthMethod;

const DESCRIPTOR_MAGIC: [u8; 2] = *b"OT";
/// Ticks only; still read for older issuances.
const DESCRIPTOR_VERSION_TICKS: u8 = 1;
/// Ticks and Verifiers, plus the Verifiers' signer key.
const DESCRIPTOR_VERSION: u8 = 2;
const DESCRIPTOR_PREFIX_LEN: usize = 5;
const DESCRIPTOR_HEADER_LEN: usize = DESCRIPTOR_PREFIX_LEN + 32;
const DESCRIPTOR_TICK_RECORD_LEN: usize = 73;
const DESCRIPTOR_RECORD_LEN: usize = DESCRIPTOR_TICK_RECORD_LEN + 1;
const TICK_RECORD: u8 = 0;
const VERIFIER_RECORD: u8 = 1;
pub(crate) const MAX_ISSUED_DESCRIPTORS: usize = 100;

/// An issued UTXO; `signer` is set for a Verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IssuedUtxoDescriptor {
    pub(crate) output_index: u32,
    pub(crate) reserve_output_index: u32,
    pub(crate) account_owner_pubkey: [u8; 32],
    pub(crate) auth_kind: u8,
    pub(crate) auth_data: [u8; 32],
    pub(crate) signer: Option<[u8; 32]>,
}

impl IssuedUtxoDescriptor {
    pub(crate) fn from_request(
        output_index: u32,
        reserve_output_index: u32,
        account_owner_pubkey: [u8; 32],
        auth: &UtxoAuthMethod,
        signer: Option<[u8; 32]>,
    ) -> Result<Self, String> {
        let (auth_kind, auth_data) = match auth.kind.as_str() {
            "asset-id-auth" => (0, decode_32(&auth.auth_data, "authentication asset id")?),
            "scriptPubKey-auth" => {
                let script = Script::from(
                    hex::decode(&auth.auth_data)
                        .map_err(|_| "invalid authentication scriptPubKey")?,
                );
                (1, hash_script(&script))
            }
            "signature-auth" => (2, decode_32(&auth.auth_data, "authentication public key")?),
            _ => return Err("unsupported issued UTXO authentication method".into()),
        };

        Ok(Self {
            output_index,
            reserve_output_index,
            account_owner_pubkey,
            auth_kind,
            auth_data,
            signer,
        })
    }

    pub(crate) fn is_verifier(&self) -> bool {
        self.signer.is_some()
    }

    pub(crate) fn script_pubkey(descriptors: &[Self]) -> Result<Script, String> {
        if descriptors.len() > MAX_ISSUED_DESCRIPTORS {
            return Err("too many issued UTXO descriptors".into());
        }
        let descriptor_count =
            u16::try_from(descriptors.len()).map_err(|_| "too many issued UTXO descriptors")?;
        if descriptors.is_empty() {
            return Err("issued UTXO descriptors cannot be empty".into());
        }
        let signer = shared_signer(descriptors)?;

        let mut data =
            Vec::with_capacity(DESCRIPTOR_HEADER_LEN + descriptors.len() * DESCRIPTOR_RECORD_LEN);
        data.extend_from_slice(&DESCRIPTOR_MAGIC);
        data.push(DESCRIPTOR_VERSION);
        data.extend_from_slice(&descriptor_count.to_be_bytes());
        data.extend_from_slice(&signer.unwrap_or([0; 32]));
        for descriptor in descriptors {
            data.extend_from_slice(&descriptor.output_index.to_be_bytes());
            data.extend_from_slice(&descriptor.reserve_output_index.to_be_bytes());
            data.extend_from_slice(&descriptor.account_owner_pubkey);
            data.push(descriptor.auth_kind);
            data.extend_from_slice(&descriptor.auth_data);
            data.push(if descriptor.is_verifier() {
                VERIFIER_RECORD
            } else {
                TICK_RECORD
            });
        }
        Ok(Script::new_op_return(&data))
    }

    pub(crate) fn from_script(script: &Script) -> Result<Option<Vec<Self>>, String> {
        let mut instructions = script.instructions_minimal();
        if !matches!(
            instructions.next(),
            Some(Ok(Instruction::Op(opcodes::all::OP_RETURN)))
        ) {
            return Ok(None);
        }
        let Some(Ok(Instruction::PushBytes(data))) = instructions.next() else {
            return Ok(None);
        };
        if instructions.next().is_some()
            || data.len() < DESCRIPTOR_MAGIC.len()
            || data[..DESCRIPTOR_MAGIC.len()] != DESCRIPTOR_MAGIC
        {
            return Ok(None);
        }
        if data.len() < DESCRIPTOR_PREFIX_LEN {
            return Err("invalid issued UTXO descriptor".into());
        }
        let (header_len, record_len) = match data[2] {
            DESCRIPTOR_VERSION_TICKS => (DESCRIPTOR_PREFIX_LEN, DESCRIPTOR_TICK_RECORD_LEN),
            DESCRIPTOR_VERSION => (DESCRIPTOR_HEADER_LEN, DESCRIPTOR_RECORD_LEN),
            _ => return Err("invalid issued UTXO descriptor".into()),
        };
        let count = usize::from(u16::from_be_bytes(data[3..5].try_into().unwrap()));
        if count == 0
            || count > MAX_ISSUED_DESCRIPTORS
            || data.len() != header_len + count * record_len
        {
            return Err("invalid issued UTXO descriptor count".into());
        }
        let header_signer: [u8; 32] = if header_len == DESCRIPTOR_HEADER_LEN {
            data[DESCRIPTOR_PREFIX_LEN..DESCRIPTOR_HEADER_LEN]
                .try_into()
                .unwrap()
        } else {
            [0; 32]
        };

        let mut descriptors = Vec::with_capacity(count);
        for record in data[header_len..].chunks_exact(record_len) {
            let auth_kind = record[40];
            if auth_kind > 2 {
                return Err("invalid issued UTXO authentication kind".into());
            }
            let signer = match record.get(DESCRIPTOR_TICK_RECORD_LEN).copied() {
                None | Some(TICK_RECORD) => None,
                Some(VERIFIER_RECORD) => Some(header_signer),
                Some(_) => return Err("invalid issued UTXO asset kind".into()),
            };
            descriptors.push(Self {
                output_index: u32::from_be_bytes(record[0..4].try_into().unwrap()),
                reserve_output_index: u32::from_be_bytes(record[4..8].try_into().unwrap()),
                account_owner_pubkey: record[8..40].try_into().unwrap(),
                auth_kind,
                auth_data: record[41..73].try_into().unwrap(),
                signer,
            });
        }
        // A signer is named only if some record is a Verifier.
        if shared_signer(&descriptors)?.unwrap_or([0; 32]) != header_signer {
            return Err("issued UTXO descriptor names a signer no Verifier carries".into());
        }
        Ok(Some(descriptors))
    }

    pub(crate) fn auth_method_name(&self) -> &'static str {
        match self.auth_kind {
            0 => "asset-id-auth",
            1 => "scriptPubKey-auth",
            2 => "signature-auth",
            _ => unreachable!("descriptor authentication kind is validated"),
        }
    }

    pub(crate) fn voucher_program(
        &self,
        storm_eye_asset_id: [u8; 32],
    ) -> Result<VoucherProgram, String> {
        voucher_program(
            storm_eye_asset_id,
            self.auth_kind,
            self.auth_data,
            self.signer,
        )
    }

    pub(crate) fn matches_script(
        &self,
        storm_eye_asset_id: [u8; 32],
        network: &SimplicityNetwork,
        script: &Script,
    ) -> bool {
        self.voucher_program(storm_eye_asset_id)
            .is_ok_and(|program| program.get_script_pubkey(network) == *script)
    }
}

/// Voucher covenant; a Verifier's internal key is its signer.
pub(crate) fn voucher_program(
    storm_eye_asset_id: [u8; 32],
    auth_kind: u8,
    auth_data: [u8; 32],
    signer: Option<[u8; 32]>,
) -> Result<VoucherProgram, String> {
    let mut arguments = VoucherArguments {
        storm_eye_asset_id,
        auth_method: u32::from(auth_kind),
        auth_asset_id: [0; 32],
        auth_script_hash: [0; 32],
        auth_pubkey: [0; 32],
    };
    match auth_kind {
        0 => arguments.auth_asset_id = auth_data,
        1 => arguments.auth_script_hash = auth_data,
        2 => arguments.auth_pubkey = auth_data,
        _ => return Err("unsupported issued UTXO authentication method".into()),
    }
    let program = VoucherProgram::new(&arguments);
    let Some(signer) = signer else {
        return Ok(program);
    };
    let signer =
        XOnlyPublicKey::from_slice(&signer).map_err(|_| "invalid Oracle Verifier signer key")?;

    Ok(program.with_taproot_pubkey(signer))
}

/// All Verifiers of one issuance share a signer.
fn shared_signer(descriptors: &[IssuedUtxoDescriptor]) -> Result<Option<[u8; 32]>, String> {
    let mut signers = descriptors
        .iter()
        .filter_map(|descriptor| descriptor.signer);
    let Some(signer) = signers.next() else {
        return Ok(None);
    };
    if signers.any(|other| other != signer) {
        return Err("Oracle Verifiers of one issuance name different signers".into());
    }
    if signer == [0; 32] {
        return Err("invalid Oracle Verifier signer key".into());
    }
    Ok(Some(signer))
}

fn decode_32(encoded: &str, name: &str) -> Result<[u8; 32], String> {
    hex::decode(encoded)
        .map_err(|_| format!("invalid {name}"))?
        .try_into()
        .map_err(|_| format!("invalid {name} length"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNER: [u8; 32] = [
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ];

    fn descriptor(output_index: u32, signer: Option<[u8; 32]>) -> IssuedUtxoDescriptor {
        IssuedUtxoDescriptor {
            output_index,
            reserve_output_index: 4,
            account_owner_pubkey: [3; 32],
            auth_kind: 2,
            auth_data: [5; 32],
            signer,
        }
    }

    #[test]
    fn descriptors_round_trip_through_one_op_return() {
        let descriptors = vec![
            descriptor(2, None),
            IssuedUtxoDescriptor {
                output_index: 3,
                reserve_output_index: 5,
                account_owner_pubkey: [6; 32],
                auth_kind: 0,
                auth_data: [7; 32],
                signer: Some(SIGNER),
            },
        ];

        assert_eq!(
            IssuedUtxoDescriptor::from_script(
                &IssuedUtxoDescriptor::script_pubkey(&descriptors).unwrap()
            )
            .unwrap(),
            Some(descriptors)
        );
    }

    #[test]
    fn reads_tick_descriptors_written_before_the_verifier() {
        let mut data = Vec::new();
        data.extend_from_slice(&DESCRIPTOR_MAGIC);
        data.push(DESCRIPTOR_VERSION_TICKS);
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend_from_slice(&4u32.to_be_bytes());
        data.extend_from_slice(&[3; 32]);
        data.push(2);
        data.extend_from_slice(&[5; 32]);

        assert_eq!(
            IssuedUtxoDescriptor::from_script(&Script::new_op_return(&data)).unwrap(),
            Some(vec![descriptor(2, None)])
        );
    }

    #[test]
    fn verifiers_of_one_issuance_share_the_signing_branch() {
        let mut other = SIGNER;
        other[31] ^= 1;

        assert!(
            IssuedUtxoDescriptor::script_pubkey(&[
                descriptor(2, Some(SIGNER)),
                descriptor(3, Some(other)),
            ])
            .is_err()
        );
    }

    #[test]
    fn rejects_a_signer_no_verifier_carries() {
        let mut script = IssuedUtxoDescriptor::script_pubkey(&[descriptor(2, None)])
            .unwrap()
            .into_bytes();
        let data_len = DESCRIPTOR_HEADER_LEN + DESCRIPTOR_RECORD_LEN;
        let signer_offset = script.len() - data_len + DESCRIPTOR_PREFIX_LEN;
        script[signer_offset] = 1;

        assert!(IssuedUtxoDescriptor::from_script(&Script::from(script)).is_err());
    }

    #[test]
    fn commits_a_verifier_to_its_signer_through_the_internal_key() {
        let storm_eye = [8; 32];
        let tick = descriptor(2, None).voucher_program(storm_eye).unwrap();
        let verifier = descriptor(2, Some(SIGNER))
            .voucher_program(storm_eye)
            .unwrap();
        let network = SimplicityNetwork::default_regtest();

        assert_eq!(tick.get_tapleaf_hash(), verifier.get_tapleaf_hash());
        assert_ne!(
            tick.get_script_pubkey(&network),
            verifier.get_script_pubkey(&network)
        );
        assert!(
            descriptor(2, Some([0; 32]))
                .voucher_program(storm_eye)
                .is_err()
        );
    }

    #[test]
    fn ignores_unrelated_op_return_and_rejects_unsupported_version() {
        assert_eq!(
            IssuedUtxoDescriptor::from_script(&Script::new_op_return(b"other")).unwrap(),
            None
        );

        let mut script = IssuedUtxoDescriptor::script_pubkey(&[descriptor(2, None)])
            .unwrap()
            .into_bytes();
        let data_len = DESCRIPTOR_HEADER_LEN + DESCRIPTOR_RECORD_LEN;
        let version_offset = script.len() - data_len + 2;
        script[version_offset] = 3;
        assert!(IssuedUtxoDescriptor::from_script(&Script::from(script)).is_err());
    }
}
