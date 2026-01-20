//! Storage trait for field-level ratchet state persistence.

use crate::error::StorageError;

/// A 32-byte session identifier.
pub type SessionId = [u8; 32];

/// Field-level storage interface for ratchet state.
///
/// This trait provides granular storage operations that are called automatically
/// during ratchet operations. Each method persists only the fields that changed.
pub trait RatchetStore: Send + Sync {
    /// Store the root key and chain keys after a DH ratchet step.
    fn store_root_and_chains(
        &self,
        session_id: &SessionId,
        root_key: &[u8; 32],
        sending_chain: Option<&[u8; 32]>,
        receiving_chain: Option<&[u8; 32]>,
    ) -> Result<(), StorageError>;

    /// Store our DH keypair (secret encrypted, public plaintext).
    fn store_dh_self(
        &self,
        session_id: &SessionId,
        secret: &[u8; 32],
        public: &[u8; 32],
    ) -> Result<(), StorageError>;

    /// Store the remote party's DH public key.
    fn store_dh_remote(
        &self,
        session_id: &SessionId,
        remote: Option<&[u8; 32]>,
    ) -> Result<(), StorageError>;

    /// Store message counters.
    fn store_counters(
        &self,
        session_id: &SessionId,
        msg_send: u32,
        msg_recv: u32,
        prev_chain_len: u32,
    ) -> Result<(), StorageError>;

    /// Add a skipped message key.
    fn add_skipped_key(
        &self,
        session_id: &SessionId,
        dh_public: &[u8; 32],
        msg_num: u32,
        message_key: &[u8; 32],
    ) -> Result<(), StorageError>;

    /// Remove a skipped message key (after use).
    fn remove_skipped_key(
        &self,
        session_id: &SessionId,
        dh_public: &[u8; 32],
        msg_num: u32,
    ) -> Result<(), StorageError>;

    /// Load all state for a session. Returns None if session doesn't exist.
    fn load_state(&self, session_id: &SessionId) -> Result<Option<StoredState>, StorageError>;

    /// Initialize a new session with all fields.
    fn init_session(
        &self,
        session_id: &SessionId,
        root_key: &[u8; 32],
        sending_chain: Option<&[u8; 32]>,
        receiving_chain: Option<&[u8; 32]>,
        dh_self_secret: &[u8; 32],
        dh_self_public: &[u8; 32],
        dh_remote: Option<&[u8; 32]>,
        msg_send: u32,
        msg_recv: u32,
        prev_chain_len: u32,
    ) -> Result<(), StorageError>;

    /// Delete a session and all its data.
    fn delete_session(&self, session_id: &SessionId) -> Result<bool, StorageError>;

    /// Check if a session exists.
    fn session_exists(&self, session_id: &SessionId) -> Result<bool, StorageError>;

    /// List all session IDs.
    fn list_sessions(&self) -> Result<Vec<SessionId>, StorageError>;
}

/// Complete state loaded from storage.
#[derive(Debug, Clone)]
pub struct StoredState {
    pub root_key: [u8; 32],
    pub sending_chain: Option<[u8; 32]>,
    pub receiving_chain: Option<[u8; 32]>,
    pub dh_self_secret: [u8; 32],
    pub dh_self_public: [u8; 32],
    pub dh_remote: Option<[u8; 32]>,
    pub msg_send: u32,
    pub msg_recv: u32,
    pub prev_chain_len: u32,
    pub skipped_keys: Vec<SkippedKeyEntry>,
}

/// A skipped key entry from storage.
#[derive(Debug, Clone)]
pub struct SkippedKeyEntry {
    pub dh_public: [u8; 32],
    pub msg_num: u32,
    pub message_key: [u8; 32],
}
