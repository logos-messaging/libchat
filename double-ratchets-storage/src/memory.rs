//! In-memory storage implementation for testing.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::StorageError;
use crate::traits::{RatchetStorage, SessionId};
use crate::types::StorableRatchetState;

/// In-memory storage backend for testing purposes.
///
/// This implementation stores ratchet states in a `HashMap` wrapped in a `RwLock`
/// for thread-safe access. Data is not persisted across process restarts.
///
/// # Example
///
/// ```
/// use double_ratchets_storage::{MemoryStorage, RatchetStorage};
///
/// let storage = MemoryStorage::new();
/// assert!(storage.list_sessions().unwrap().is_empty());
/// ```
pub struct MemoryStorage {
    states: RwLock<HashMap<SessionId, StorableRatchetState>>,
}

impl MemoryStorage {
    /// Create a new empty in-memory storage.
    pub fn new() -> Self {
        Self {
            states: RwLock::new(HashMap::new()),
        }
    }

    /// Get the number of stored sessions.
    pub fn len(&self) -> usize {
        self.states.read().unwrap().len()
    }

    /// Check if the storage is empty.
    pub fn is_empty(&self) -> bool {
        self.states.read().unwrap().is_empty()
    }

    /// Clear all stored sessions.
    pub fn clear(&self) {
        self.states.write().unwrap().clear();
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl RatchetStorage for MemoryStorage {
    fn save(&self, session_id: &SessionId, state: &StorableRatchetState) -> Result<(), StorageError> {
        let mut states = self.states.write().unwrap();
        states.insert(*session_id, state.clone());
        Ok(())
    }

    fn load(&self, session_id: &SessionId) -> Result<Option<StorableRatchetState>, StorageError> {
        let states = self.states.read().unwrap();
        Ok(states.get(session_id).cloned())
    }

    fn delete(&self, session_id: &SessionId) -> Result<bool, StorageError> {
        let mut states = self.states.write().unwrap();
        Ok(states.remove(session_id).is_some())
    }

    fn exists(&self, session_id: &SessionId) -> Result<bool, StorageError> {
        let states = self.states.read().unwrap();
        Ok(states.contains_key(session_id))
    }

    fn list_sessions(&self) -> Result<Vec<SessionId>, StorageError> {
        let states = self.states.read().unwrap();
        Ok(states.keys().copied().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use double_ratchets::hkdf::DefaultDomain;
    use double_ratchets::state::RatchetState;
    use double_ratchets::InstallationKeyPair;

    fn create_test_state() -> StorableRatchetState {
        let bob_keypair = InstallationKeyPair::generate();
        let shared_secret = [0x42u8; 32];
        let state: RatchetState<DefaultDomain> =
            RatchetState::init_sender(shared_secret, *bob_keypair.public());
        StorableRatchetState::from_ratchet_state(&state, "default")
    }

    #[test]
    fn test_save_and_load() {
        let storage = MemoryStorage::new();
        let session_id = [1u8; 32];
        let state = create_test_state();

        storage.save(&session_id, &state).unwrap();
        let loaded = storage.load(&session_id).unwrap();

        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.root_key, state.root_key);
    }

    #[test]
    fn test_load_nonexistent() {
        let storage = MemoryStorage::new();
        let session_id = [1u8; 32];

        let loaded = storage.load(&session_id).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_delete() {
        let storage = MemoryStorage::new();
        let session_id = [1u8; 32];
        let state = create_test_state();

        storage.save(&session_id, &state).unwrap();
        assert!(storage.exists(&session_id).unwrap());

        let deleted = storage.delete(&session_id).unwrap();
        assert!(deleted);
        assert!(!storage.exists(&session_id).unwrap());

        // Deleting again should return false
        let deleted = storage.delete(&session_id).unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_exists() {
        let storage = MemoryStorage::new();
        let session_id = [1u8; 32];

        assert!(!storage.exists(&session_id).unwrap());

        let state = create_test_state();
        storage.save(&session_id, &state).unwrap();

        assert!(storage.exists(&session_id).unwrap());
    }

    #[test]
    fn test_list_sessions() {
        let storage = MemoryStorage::new();

        assert!(storage.list_sessions().unwrap().is_empty());

        let state = create_test_state();
        let session_ids: Vec<SessionId> = (0..3).map(|i| [i; 32]).collect();

        for id in &session_ids {
            storage.save(id, &state).unwrap();
        }

        let mut listed = storage.list_sessions().unwrap();
        listed.sort();
        let mut expected = session_ids.clone();
        expected.sort();

        assert_eq!(listed, expected);
    }

    #[test]
    fn test_overwrite() {
        let storage = MemoryStorage::new();
        let session_id = [1u8; 32];

        // Create first state
        let bob_keypair1 = InstallationKeyPair::generate();
        let state1: RatchetState<DefaultDomain> =
            RatchetState::init_sender([0x42u8; 32], *bob_keypair1.public());
        let storable1 = StorableRatchetState::from_ratchet_state(&state1, "default");

        // Create second state with different root
        let bob_keypair2 = InstallationKeyPair::generate();
        let state2: RatchetState<DefaultDomain> =
            RatchetState::init_sender([0x43u8; 32], *bob_keypair2.public());
        let storable2 = StorableRatchetState::from_ratchet_state(&state2, "default");

        // Save first, then overwrite with second
        storage.save(&session_id, &storable1).unwrap();
        storage.save(&session_id, &storable2).unwrap();

        // Should have the second state
        let loaded = storage.load(&session_id).unwrap().unwrap();
        assert_eq!(loaded.root_key, storable2.root_key);
        assert_ne!(loaded.root_key, storable1.root_key);
    }

    #[test]
    fn test_clear() {
        let storage = MemoryStorage::new();
        let state = create_test_state();

        for i in 0..5 {
            storage.save(&[i; 32], &state).unwrap();
        }

        assert_eq!(storage.len(), 5);

        storage.clear();
        assert!(storage.is_empty());
    }
}
