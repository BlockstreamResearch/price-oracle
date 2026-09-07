use contracts::artifacts::tick_asset::{TickAssetProgram, derived_tick_asset::TickAssetArguments};
use simplex::{
    provider::SimplicityNetwork,
    simplicityhl::elements::{Script, opcodes, script::Instruction},
    utils::hash_script,
};

use crate::external_api::users::UtxoAuthMethod;

const DESCRIPTOR_MAGIC: [u8; 2] = *b"OT";
const DESCRIPTOR_VERSION: u8 = 1;
const DESCRIPTOR_HEADER_LEN: usize = 5;
const DESCRIPTOR_RECORD_LEN: usize = 73;
pub(crate) const MAX_ISSUED_TICK_DESCRIPTORS: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IssuedTickDescriptor {
    pub(crate) tick_output_index: u32,
    pub(crate) reserve_output_index: u32,
    pub(crate) account_owner_pubkey: [u8; 32],
    pub(crate) auth_kind: u8,
    pub(crate) auth_data: [u8; 32],
}

impl IssuedTickDescriptor {
    pub(crate) fn from_request(
        tick_output_index: u32,
        reserve_output_index: u32,
        account_owner_pubkey: [u8; 32],
        auth: &UtxoAuthMethod,
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
            _ => return Err("unsupported Tick authentication method".into()),
        };

        Ok(Self {
            tick_output_index,
            reserve_output_index,
            account_owner_pubkey,
            auth_kind,
            auth_data,
        })
    }

    pub(crate) fn script_pubkey(descriptors: &[Self]) -> Result<Script, String> {
        if descriptors.len() > MAX_ISSUED_TICK_DESCRIPTORS {
            return Err("too many issued Tick descriptors".into());
        }
        let descriptor_count =
            u16::try_from(descriptors.len()).map_err(|_| "too many issued Tick descriptors")?;
        if descriptors.is_empty() {
            return Err("issued Tick descriptors cannot be empty".into());
        }

        let mut data =
            Vec::with_capacity(DESCRIPTOR_HEADER_LEN + descriptors.len() * DESCRIPTOR_RECORD_LEN);
        data.extend_from_slice(&DESCRIPTOR_MAGIC);
        data.push(DESCRIPTOR_VERSION);
        data.extend_from_slice(&descriptor_count.to_be_bytes());
        for descriptor in descriptors {
            data.extend_from_slice(&descriptor.tick_output_index.to_be_bytes());
            data.extend_from_slice(&descriptor.reserve_output_index.to_be_bytes());
            data.extend_from_slice(&descriptor.account_owner_pubkey);
            data.push(descriptor.auth_kind);
            data.extend_from_slice(&descriptor.auth_data);
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
        if data.len() < DESCRIPTOR_HEADER_LEN || data[2] != DESCRIPTOR_VERSION {
            return Err("invalid issued Tick descriptor".into());
        }
        let count = usize::from(u16::from_be_bytes(data[3..5].try_into().unwrap()));
        if count == 0
            || count > MAX_ISSUED_TICK_DESCRIPTORS
            || data.len() != DESCRIPTOR_HEADER_LEN + count * DESCRIPTOR_RECORD_LEN
        {
            return Err("invalid issued Tick descriptor count".into());
        }

        let mut descriptors = Vec::with_capacity(count);
        for record in data[DESCRIPTOR_HEADER_LEN..].chunks_exact(DESCRIPTOR_RECORD_LEN) {
            let auth_kind = record[40];
            if auth_kind > 2 {
                return Err("invalid issued Tick authentication kind".into());
            }
            descriptors.push(Self {
                tick_output_index: u32::from_be_bytes(record[0..4].try_into().unwrap()),
                reserve_output_index: u32::from_be_bytes(record[4..8].try_into().unwrap()),
                account_owner_pubkey: record[8..40].try_into().unwrap(),
                auth_kind,
                auth_data: record[41..73].try_into().unwrap(),
            });
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

    pub(crate) fn tick_program(&self, storm_eye_asset_id: [u8; 32]) -> TickAssetProgram {
        let mut arguments = TickAssetArguments {
            storm_eye_asset_id,
            auth_method: self.auth_kind as u32,
            auth_asset_id: [0; 32],
            auth_script_hash: [0; 32],
            auth_pubkey: [0; 32],
        };
        match self.auth_kind {
            0 => arguments.auth_asset_id = self.auth_data,
            1 => arguments.auth_script_hash = self.auth_data,
            2 => arguments.auth_pubkey = self.auth_data,
            _ => unreachable!("descriptor authentication kind is validated"),
        }
        TickAssetProgram::new(&arguments)
    }

    pub(crate) fn matches_tick_script(
        &self,
        storm_eye_asset_id: [u8; 32],
        network: &SimplicityNetwork,
        script: &Script,
    ) -> bool {
        self.tick_program(storm_eye_asset_id)
            .get_script_pubkey(network)
            == *script
    }
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

    #[test]
    fn descriptors_round_trip_through_one_op_return() {
        let descriptors = vec![
            IssuedTickDescriptor {
                tick_output_index: 2,
                reserve_output_index: 4,
                account_owner_pubkey: [3; 32],
                auth_kind: 2,
                auth_data: [5; 32],
            },
            IssuedTickDescriptor {
                tick_output_index: 3,
                reserve_output_index: 5,
                account_owner_pubkey: [6; 32],
                auth_kind: 0,
                auth_data: [7; 32],
            },
        ];

        assert_eq!(
            IssuedTickDescriptor::from_script(
                &IssuedTickDescriptor::script_pubkey(&descriptors).unwrap()
            )
            .unwrap(),
            Some(descriptors)
        );
    }

    #[test]
    fn ignores_unrelated_op_return_and_rejects_unsupported_version() {
        assert_eq!(
            IssuedTickDescriptor::from_script(&Script::new_op_return(b"other")).unwrap(),
            None
        );

        let descriptors = [IssuedTickDescriptor {
            tick_output_index: 2,
            reserve_output_index: 4,
            account_owner_pubkey: [3; 32],
            auth_kind: 2,
            auth_data: [5; 32],
        }];
        let mut script = IssuedTickDescriptor::script_pubkey(&descriptors)
            .unwrap()
            .into_bytes();
        let data_len = DESCRIPTOR_HEADER_LEN + DESCRIPTOR_RECORD_LEN;
        let version_offset = script.len() - data_len + 2;
        script[version_offset] = 2;
        assert!(IssuedTickDescriptor::from_script(&Script::from(script)).is_err());
    }
}
