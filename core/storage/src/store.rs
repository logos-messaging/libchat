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
    PrivateV1,
    Unknown(String),
}

impl ConversationKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::PrivateV1 => "private_v1",
            Self::Unknown(value) => value.as_str(),
        }
    }
}

impl From<&str> for ConversationKind {
    fn from(value: &str) -> Self {
        match value {
            "private_v1" => Self::PrivateV1,
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

/// Raw state data for ratchet storage (without generic parameter).
#[derive(Debug, Clone)]
pub struct RatchetStateRecord {
    pub root_key: [u8; 32],
    pub sending_chain: Option<[u8; 32]>,
    pub receiving_chain: Option<[u8; 32]>,
    pub dh_self_secret: [u8; 32],
    pub dh_remote: Option<[u8; 32]>,
    pub msg_send: u32,
    pub msg_recv: u32,
    pub prev_chain_len: u32,
}

/// A skipped message key stored alongside ratchet state.
#[derive(Debug, Clone)]
pub struct SkippedKeyRecord {
    pub public_key: [u8; 32],
    pub msg_num: u32,
    pub message_key: [u8; 32],
}

/// Persistence operations for double-ratchet state.
pub trait RatchetStore {
    /// Saves ratchet state and skipped keys for a conversation.
    fn save_ratchet_state(
        &mut self,
        conversation_id: &str,
        state: &RatchetStateRecord,
        skipped_keys: &[SkippedKeyRecord],
    ) -> Result<(), StorageError>;

    /// Loads ratchet state for a conversation.
    fn load_ratchet_state(&self, conversation_id: &str)
    -> Result<RatchetStateRecord, StorageError>;

    /// Loads skipped keys for a conversation.
    fn load_skipped_keys(
        &self,
        conversation_id: &str,
    ) -> Result<Vec<SkippedKeyRecord>, StorageError>;

    /// Checks if a ratchet state exists for a conversation.
    fn has_ratchet_state(&self, conversation_id: &str) -> Result<bool, StorageError>;

    /// Deletes ratchet state and skipped keys for a conversation.
    fn delete_ratchet_state(&mut self, conversation_id: &str) -> Result<(), StorageError>;

    /// Cleans up old skipped keys older than the given age in seconds.
    fn cleanup_old_skipped_keys(&mut self, max_age_secs: i64) -> Result<usize, StorageError>;
}

pub trait ChatStore: IdentityStore + EphemeralKeyStore + ConversationStore + RatchetStore {}

impl<T> ChatStore for T where T: IdentityStore + EphemeralKeyStore + ConversationStore + RatchetStore
{}
