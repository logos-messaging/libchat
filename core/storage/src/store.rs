use crypto::{Identity, PrivateKey};

use crate::StorageError;

/// Persistence operations for installation identity data.
pub trait IdentityStore {
    /// Loads the stored identity if one exists.
    fn load_identity(&self) -> Result<Option<Identity>, StorageError>;

    /// Persists the installation identity.
    fn save_identity(&mut self, identity: &Identity) -> Result<(), StorageError>;
}

pub trait EphemeralKeyStore {
    fn save_ephemeral_key(
        &mut self,
        public_key_hex: &str,
        private_key: &PrivateKey,
    ) -> Result<(), StorageError>;

    fn load_ephemeral_key(&self, public_key_hex: &str) -> Result<Option<PrivateKey>, StorageError>;

    fn remove_ephemeral_key(&mut self, public_key_hex: &str) -> Result<(), StorageError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationKind {
    Unknown(String),
    GroupV1,
}

impl ConversationKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Unknown(value) => value.as_str(),
            Self::GroupV1 => "group_v1",
        }
    }
}

impl From<&str> for ConversationKind {
    fn from(value: &str) -> Self {
        match value {
            "group_v1" => Self::GroupV1,
            other => Self::Unknown(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationMeta {
    pub local_convo_id: String,
    pub remote_convo_id: String,
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

pub trait ChatStore: IdentityStore + EphemeralKeyStore + ConversationStore {}

impl<T> ChatStore for T where T: IdentityStore + EphemeralKeyStore + ConversationStore {}
