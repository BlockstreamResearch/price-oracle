use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use storm::{CustomMsg, StormMessage};
use storm_tree::{NodePublicKey, StormTreeBranch};

const DOMAIN: &str = "high-storm";

/// A higher-level message carried inside a Storm custom message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeMessage {
    /// Numeric identifier for the message payload.
    pub kind: u16,
    /// Hash of the message that started the associated operation.
    pub linked_to: Option<[u8; 32]>,
    /// Postcard-encoded kind-specific payload.
    pub payload: Vec<u8>,
}

impl NodeMessage {
    pub fn new<T: Serialize>(
        kind: NodeMessageKind,
        linked_to: Option<[u8; 32]>,
        payload: &T,
    ) -> Result<Self, postcard::Error> {
        Ok(Self {
            kind: kind as u16,
            linked_to,
            payload: postcard::to_stdvec(payload)?,
        })
    }

    pub(crate) fn from_custom(custom: &CustomMsg) -> Result<Option<Self>, postcard::Error> {
        if custom.domain != DOMAIN {
            return Ok(None);
        }
        postcard::from_bytes(&custom.payload).map(Some)
    }

    pub fn decoded_kind(&self) -> Option<NodeMessageKind> {
        NodeMessageKind::from_id(self.kind)
    }

    pub fn decode_payload<T: DeserializeOwned>(&self) -> Result<T, postcard::Error> {
        postcard::from_bytes(&self.payload)
    }

    pub fn hash(&self) -> Result<[u8; 32], postcard::Error> {
        Ok(Sha256::digest(postcard::to_stdvec(self)?).into())
    }

    pub fn into_storm_message(self) -> Result<StormMessage, storm::MessageError> {
        CustomMsg {
            domain: DOMAIN.to_string(),
            payload: postcard::to_stdvec(&self)?,
        }
        .into_storm_message()
    }
}

/// Node message kinds defined by the Oracle Network specification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum NodeMessageKind {
    ExecuteUserRequests = 0,
    ExchangeRewards = 1,
    SigningNonces = 2,
    PartialSignatures = 3,
    BurnExpiredUtxos = 4,
    ExpiredUtxosBurned = 5,
    NetworkVoteRequest = 6,
    ApproveVotingRequest = 7,
    AskAboutVotings = 8,
    ExecuteVotingRequest = 9,
    AttestPrice = 10,
    NetworkAssets = 11,
    RenewStormUtxos = 12,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum NetworkVoteKind {
    UpdateNetworkMembers = 0,
    MergeStormEyes = 1,
    SplitStormEye = 2,
}

impl NetworkVoteKind {
    pub fn from_id(id: u16) -> Option<Self> {
        Some(match id {
            0 => Self::UpdateNetworkMembers,
            1 => Self::MergeStormEyes,
            2 => Self::SplitStormEye,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkVoteRequest {
    pub kind: u16,
    pub payload: Vec<u8>,
}

impl NetworkVoteRequest {
    pub fn new<T: Serialize>(kind: NetworkVoteKind, payload: &T) -> Result<Self, postcard::Error> {
        Ok(Self {
            kind: kind as u16,
            payload: postcard::to_stdvec(payload)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateNetworkMembers {
    pub to_accept: Vec<NodePublicKey>,
    pub to_remove: Vec<NodePublicKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StormEyeUtxo {
    pub txid: [u8; 32],
    pub output_index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAsset {
    pub kind: String,
    pub name: String,
    pub asset_id: [u8; 32],
    pub reissuance_token_id: Option<[u8; 32]>,
    pub entropy: Option<[u8; 32]>,
    pub issuance_txid: [u8; 32],
    pub contract_script: Vec<u8>,
    pub contract_data: Option<Vec<u8>>,
    pub supply: u64,
    pub created_at_block: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAssets {
    pub assets: Vec<NetworkAsset>,
    pub snapshot_id: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalRequests {
    pub request_hash: [u8; 32],
    pub network_user_requests: Vec<u8>,
    pub additional_payload: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecuteUserRequests {
    pub tx: Vec<u8>,
    pub signing_hash: [u8; 32],
    pub signing_storm_tree_branch: StormTreeBranch,
    pub external_requests: Vec<ExternalRequests>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeStormEyes {
    pub utxos_to_merge: Vec<StormEyeUtxo>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitStormEye {
    pub utxo_to_split: StormEyeUtxo,
    pub number_of_splits: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproveVotingRequest {
    pub public_key: NodePublicKey,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VotingSyncApproval {
    pub(crate) message: Vec<u8>,
    pub(crate) block_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VotingSyncRequest {
    pub(crate) message_hash: [u8; 32],
    pub(crate) message: Vec<u8>,
    pub(crate) block_height: u64,
    pub(crate) approvals: Vec<VotingSyncApproval>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VotingSyncMessage {
    pub(crate) is_response: bool,
    pub(crate) requests: Vec<VotingSyncRequest>,
}

impl NodeMessageKind {
    pub(crate) fn from_id(id: u16) -> Option<Self> {
        Some(match id {
            0 => Self::ExecuteUserRequests,
            1 => Self::ExchangeRewards,
            2 => Self::SigningNonces,
            3 => Self::PartialSignatures,
            4 => Self::BurnExpiredUtxos,
            5 => Self::ExpiredUtxosBurned,
            6 => Self::NetworkVoteRequest,
            7 => Self::ApproveVotingRequest,
            8 => Self::AskAboutVotings,
            9 => Self::ExecuteVotingRequest,
            10 => Self::AttestPrice,
            11 => Self::NetworkAssets,
            12 => Self::RenewStormUtxos,
            _ => return None,
        })
    }

    pub(crate) fn requires_coordinator(self) -> bool {
        matches!(self, Self::ExecuteUserRequests | Self::NetworkAssets)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SigningNoncesMessage {
    pub(crate) signer: NodePublicKey,
    pub(crate) nonces: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PartialSignaturesMessage {
    pub(crate) signer: NodePublicKey,
    pub(crate) partial_signatures: Vec<[u8; 32]>,
}
