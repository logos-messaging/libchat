//! Storage trait for double ratchet persistence.
//!
//! This module defines the `RatchetStore` trait that abstracts storage needs
//! for the double ratchet algorithm. Implementations can be backed by SQLite,
//! PostgreSQL, in-memory storage, or any other backend.

use crate::{
    keypair::InstallationKeyPair,
    types::{ChainKey, MessageKey, RootKey},
};

/// Identifier for a skipped message key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SkippedKeyId {
    pub public_key: [u8; 32],
    pub msg_num: u32,
}

/// A skipped message key with its identifier.
#[derive(Debug, Clone)]
pub struct SkippedMessageKey {
    pub id: SkippedKeyId,
    pub message_key: MessageKey,
}

/// The core ratchet state that needs to be persisted.
#[derive(Debug, Clone)]
pub struct RatchetStateData {
    pub root_key: RootKey,
    pub sending_chain: Option<ChainKey>,
    pub receiving_chain: Option<ChainKey>,
    pub dh_self: InstallationKeyPair,
    pub dh_remote: Option<[u8; 32]>,
    pub msg_send: u32,
    pub msg_recv: u32,
    pub prev_chain_len: u32,
}

/// Error type for store operations.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("already exists: {0}")]
    AlreadyExists(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Trait defining storage requirements for the double ratchet algorithm.
///
/// This trait abstracts the storage layer, allowing the double ratchet
/// implementation to be agnostic to the underlying storage mechanism.
///
/// # Example Implementations
///
/// - `SqliteRatchetStore` - SQLite/SQLCipher backed storage
/// - `EphemeralStore` - In-memory storage for testing
/// - `PostgresRatchetStore` - PostgreSQL backed storage (external)
pub trait RatchetStore {
    // === Ratchet State Operations ===

    /// Saves the ratchet state for a conversation.
    fn save_state(
        &mut self,
        conversation_id: &str,
        state: &RatchetStateData,
    ) -> Result<(), StoreError>;

    /// Loads the ratchet state for a conversation.
    fn load_state(&self, conversation_id: &str) -> Result<RatchetStateData, StoreError>;

    /// Checks if a conversation exists.
    fn exists(&self, conversation_id: &str) -> Result<bool, StoreError>;

    /// Deletes a conversation and all its associated data.
    fn delete(&mut self, conversation_id: &str) -> Result<(), StoreError>;

    // === Skipped Message Key Operations ===

    /// Gets a skipped message key if it exists.
    fn get_skipped_key(
        &self,
        conversation_id: &str,
        id: &SkippedKeyId,
    ) -> Result<Option<MessageKey>, StoreError>;

    /// Adds a skipped message key.
    fn add_skipped_key(
        &mut self,
        conversation_id: &str,
        key: SkippedMessageKey,
    ) -> Result<(), StoreError>;

    /// Removes a skipped message key (after successful decryption).
    fn remove_skipped_key(
        &mut self,
        conversation_id: &str,
        id: &SkippedKeyId,
    ) -> Result<(), StoreError>;

    /// Gets all skipped keys for a conversation.
    fn get_all_skipped_keys(
        &self,
        conversation_id: &str,
    ) -> Result<Vec<SkippedMessageKey>, StoreError>;

    /// Clears all skipped keys for a conversation.
    fn clear_skipped_keys(&mut self, conversation_id: &str) -> Result<(), StoreError>;
}
