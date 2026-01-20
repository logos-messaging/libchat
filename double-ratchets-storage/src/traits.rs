//! Storage trait definitions.

use crate::error::StorageError;
use crate::types::StorableRatchetState;

/// A 32-byte session identifier.
pub type SessionId = [u8; 32];

/// Abstract storage interface for ratchet states.
///
/// Implementations must be thread-safe (`Send + Sync`).
pub trait RatchetStorage: Send + Sync {
    /// Save a ratchet state for the given session.
    ///
    /// If a state already exists for this session, it will be overwritten.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Unique identifier for the session.
    /// * `state` - The ratchet state to store.
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success.
    /// * `Err(StorageError)` on failure.
    fn save(&self, session_id: &SessionId, state: &StorableRatchetState) -> Result<(), StorageError>;

    /// Load a ratchet state for the given session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Unique identifier for the session.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(state))` if found.
    /// * `Ok(None)` if not found.
    /// * `Err(StorageError)` on failure.
    fn load(&self, session_id: &SessionId) -> Result<Option<StorableRatchetState>, StorageError>;

    /// Delete a ratchet state for the given session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Unique identifier for the session.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if the session existed and was deleted.
    /// * `Ok(false)` if the session did not exist.
    /// * `Err(StorageError)` on failure.
    fn delete(&self, session_id: &SessionId) -> Result<bool, StorageError>;

    /// Check if a session exists in storage.
    ///
    /// # Arguments
    ///
    /// * `session_id` - Unique identifier for the session.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if the session exists.
    /// * `Ok(false)` if the session does not exist.
    /// * `Err(StorageError)` on failure.
    fn exists(&self, session_id: &SessionId) -> Result<bool, StorageError>;

    /// List all session IDs in storage.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<SessionId>)` containing all session IDs.
    /// * `Err(StorageError)` on failure.
    fn list_sessions(&self) -> Result<Vec<SessionId>, StorageError>;
}
