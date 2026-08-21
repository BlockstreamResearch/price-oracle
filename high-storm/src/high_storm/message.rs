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
    pub(crate) fn new<T: Serialize>(
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

    pub(crate) fn decoded_kind(&self) -> Option<NodeMessageKind> {
        NodeMessageKind::from_id(self.kind)
    }

    pub(crate) fn decode_payload<T: DeserializeOwned>(&self) -> Result<T, postcard::Error> {
        postcard::from_bytes(&self.payload)
    }

    pub(crate) fn hash(&self) -> Result<[u8; 32], postcard::Error> {
        Ok(Sha256::digest(postcard::to_stdvec(self)?).into())
    }

    pub(crate) fn into_storm_message(self) -> Result<StormMessage, storm::MessageError> {
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
    Test = 13,
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
            13 => Self::Test,
            _ => return None,
        })
    }

    pub(crate) fn requires_coordinator(self) -> bool {
        matches!(self, Self::ExecuteUserRequests)
    }
}

/// Temporary message used to exercise signing before transaction validation exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestNodeMessage {
    /// Storm Tree branch whose participants must sign.
    pub signing_storm_tree_branch: StormTreeBranch,
    /// Already-hashed 32-byte messages to sign.
    pub message_hashes: Vec<[u8; 32]>,
    pub(crate) delayed_signer: Option<NodePublicKey>,
    pub(crate) delay_millis: u64,
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
