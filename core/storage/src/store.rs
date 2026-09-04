use std::fmt;

use crypto::Identity;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{KvStore, StorageError};

/// A delegate signer: the 32-byte Ed25519 seed its keypair is rebuilt from, and the address of
/// the account it signs for.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DelegateRecord {
    pub seed: [u8; 32],
    pub account_addr: String,
}

impl fmt::Debug for DelegateRecord {
    // Manually implement debug to not reveal the seed
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DelegateRecord")
            .field("account_addr", &self.account_addr)
            .finish_non_exhaustive()
    }
}

/// Persistence operations for installation identity data.
pub trait IdentityStore {
    /// Loads the stored identity if one exists.
    fn load_identity(&self) -> Result<Option<Identity>, StorageError>;

    /// Persists the installation identity.
    fn save_identity(&mut self, identity: &Identity) -> Result<(), StorageError>;

    /// Loads the stored delegate if one exists.
    fn load_delegate(&self) -> Result<Option<DelegateRecord>, StorageError>;

    /// Persists the delegate, replacing the one stored before it.
    fn save_delegate(&mut self, delegate: &DelegateRecord) -> Result<(), StorageError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationKind {
    Unknown(String),
    GroupV1,
    DirectV1,
    GroupV2,
}

impl ConversationKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Unknown(value) => value.as_str(),
            Self::GroupV1 => "group_v1",
            Self::DirectV1 => "direct_v1",
            Self::GroupV2 => "group_v2",
        }
    }
}

impl From<&str> for ConversationKind {
    fn from(value: &str) -> Self {
        match value {
            "group_v1" => Self::GroupV1,
            "direct_v1" => Self::DirectV1,
            "group_v2" => Self::GroupV2,
            other => Self::Unknown(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationMeta {
    pub local_convo_id: String,
    pub kind: ConversationKind,
}

pub trait ConversationStore {
    fn save_conversation(&mut self, meta: &ConversationMeta) -> Result<(), StorageError>;

    fn load_conversation(
        &self,
        local_convo_id: &str,
    ) -> Result<Option<ConversationMeta>, StorageError>;

    fn remove_conversation(&mut self, local_convo_id: &str) -> Result<(), StorageError>;

    fn load_conversations(&self) -> Result<Vec<ConversationMeta>, StorageError>;

    fn has_conversation(&self, local_convo_id: &str) -> Result<bool, StorageError>;
}

/// State the client owns, independent of any conversation.
pub trait ClientStore: IdentityStore + ConversationStore {}

impl<T> ClientStore for T where T: IdentityStore + ConversationStore {}

/// Everything libchat stores: the client's own state, and the substrate every conversation type
/// owns its state in.
pub trait Store: ClientStore + KvStore {}

impl<T> Store for T where T: ClientStore + KvStore {}
