use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};

use crate::{
    MergeStormEyes, NetworkVoteKind, NetworkVoteRequest, SplitStormEye, StormEyeUtxo,
    UpdateNetworkMembers, VotingRequest, VotingStatus,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VotingProposal {
    UpdateNetworkMembers {
        to_accept: Vec<String>,
        to_remove: Vec<String>,
    },
    MergeStormEyes {
        utxos_to_merge: Vec<Utxo>,
    },
    SplitStormEye {
        utxo_to_split: Utxo,
        number_of_splits: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Utxo {
    pub txid: String,
    pub output_index: u32,
}

#[derive(Debug, Serialize)]
pub struct VotingResponse {
    pub message_hash: String,
    pub proposal: VotingProposal,
    pub block_height: u64,
    pub status: &'static str,
    pub approvals: Vec<VotingApprovalResponse>,
}

#[derive(Debug, Serialize)]
pub struct VotingApprovalResponse {
    pub public_key: String,
    pub block_height: u64,
}

impl VotingProposal {
    pub fn into_request(self) -> Result<NetworkVoteRequest, String> {
        match self {
            Self::UpdateNetworkMembers {
                to_accept,
                to_remove,
            } => NetworkVoteRequest::new(
                NetworkVoteKind::UpdateNetworkMembers,
                &UpdateNetworkMembers {
                    to_accept: parse_public_keys(to_accept)?,
                    to_remove: parse_public_keys(to_remove)?,
                },
            ),
            Self::MergeStormEyes { utxos_to_merge } => NetworkVoteRequest::new(
                NetworkVoteKind::MergeStormEyes,
                &MergeStormEyes {
                    utxos_to_merge: utxos_to_merge
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<_, _>>()?,
                },
            ),
            Self::SplitStormEye {
                utxo_to_split,
                number_of_splits,
            } => NetworkVoteRequest::new(
                NetworkVoteKind::SplitStormEye,
                &SplitStormEye {
                    utxo_to_split: utxo_to_split.try_into()?,
                    number_of_splits,
                },
            ),
        }
        .map_err(|error| error.to_string())
    }

    fn from_request(request: &NetworkVoteRequest) -> Result<Self, String> {
        match NetworkVoteKind::from_id(request.kind).ok_or("unknown voting request kind")? {
            NetworkVoteKind::UpdateNetworkMembers => {
                let payload: UpdateNetworkMembers = decode_payload(request)?;
                Ok(Self::UpdateNetworkMembers {
                    to_accept: payload.to_accept.into_iter().map(hex::encode).collect(),
                    to_remove: payload.to_remove.into_iter().map(hex::encode).collect(),
                })
            }
            NetworkVoteKind::MergeStormEyes => {
                let payload: MergeStormEyes = decode_payload(request)?;
                Ok(Self::MergeStormEyes {
                    utxos_to_merge: payload.utxos_to_merge.into_iter().map(Into::into).collect(),
                })
            }
            NetworkVoteKind::SplitStormEye => {
                let payload: SplitStormEye = decode_payload(request)?;
                Ok(Self::SplitStormEye {
                    utxo_to_split: payload.utxo_to_split.into(),
                    number_of_splits: payload.number_of_splits,
                })
            }
        }
    }
}

impl TryFrom<VotingRequest> for VotingResponse {
    type Error = String;

    fn try_from(request: VotingRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            message_hash: hex::encode(request.message_hash),
            proposal: VotingProposal::from_request(&request.request)?,
            block_height: request.block_height,
            status: match request.status {
                VotingStatus::Pending => "pending",
                VotingStatus::Approved => "approved",
            },
            approvals: request
                .approvals
                .into_iter()
                .map(|approval| VotingApprovalResponse {
                    public_key: hex::encode(approval.public_key),
                    block_height: approval.block_height,
                })
                .collect(),
        })
    }
}

impl TryFrom<Utxo> for StormEyeUtxo {
    type Error = String;

    fn try_from(utxo: Utxo) -> Result<Self, Self::Error> {
        Ok(Self {
            txid: parse_hex_array(&utxo.txid, "transaction id")?,
            output_index: utxo.output_index,
        })
    }
}

impl From<StormEyeUtxo> for Utxo {
    fn from(utxo: StormEyeUtxo) -> Self {
        Self {
            txid: hex::encode(utxo.txid),
            output_index: utxo.output_index,
        }
    }
}

fn parse_public_keys(keys: Vec<String>) -> Result<Vec<[u8; 32]>, String> {
    keys.into_iter()
        .map(|key| {
            let bytes = hex::decode(&key).map_err(|_| format!("invalid public key '{key}'"))?;
            let bytes = bytes
                .try_into()
                .map_err(|_| format!("invalid public key '{key}'"))?;
            XOnlyPublicKey::from_byte_array(bytes)
                .map(|key| key.serialize())
                .map_err(|_| format!("invalid public key '{key}'"))
        })
        .collect()
}

fn parse_hex_array<const N: usize>(encoded: &str, name: &str) -> Result<[u8; N], String> {
    hex::decode(encoded)
        .map_err(|_| format!("invalid {name}"))?
        .try_into()
        .map_err(|_| format!("invalid {name}"))
}

fn decode_payload<T: serde::de::DeserializeOwned>(
    request: &NetworkVoteRequest,
) -> Result<T, String> {
    postcard::from_bytes(&request.payload).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_every_proposal_kind() {
        let member = XOnlyPublicKey::from_byte_array([
            0x2f, 0x8b, 0xde, 0x4d, 0x1a, 0x07, 0x20, 0x93, 0x55, 0xb4, 0xa7, 0x25, 0x0a, 0x5c,
            0x51, 0x28, 0xe8, 0x8b, 0x84, 0xbd, 0xdc, 0x61, 0x9a, 0xb7, 0xcb, 0xa8, 0xd5, 0x69,
            0xb2, 0x40, 0xef, 0xe4,
        ])
        .unwrap()
        .serialize();
        let proposals = [
            VotingProposal::UpdateNetworkMembers {
                to_accept: vec![hex::encode(member)],
                to_remove: Vec::new(),
            },
            VotingProposal::MergeStormEyes {
                utxos_to_merge: vec![utxo(1), utxo(2)],
            },
            VotingProposal::SplitStormEye {
                utxo_to_split: utxo(3),
                number_of_splits: 2,
            },
        ];

        for proposal in proposals {
            let request = proposal.into_request().unwrap();
            VotingProposal::from_request(&request).unwrap();
        }
    }

    fn utxo(byte: u8) -> Utxo {
        Utxo {
            txid: hex::encode([byte; 32]),
            output_index: byte.into(),
        }
    }
}
