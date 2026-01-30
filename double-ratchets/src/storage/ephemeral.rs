//! In-memory ephemeral storage for testing.
//!
//! This store keeps all data in memory and is useful for testing
//! or scenarios where persistence is not needed.

use std::collections::HashMap;

use super::store::{RatchetStateData, RatchetStore, SkippedKeyId, SkippedMessageKey, StoreError};

/// In-memory storage implementation.
///
/// All data is lost when the store is dropped.
#[derive(Debug, Default)]
pub struct EphemeralStore {
    states: HashMap<String, RatchetStateData>,
    skipped_keys: HashMap<String, HashMap<SkippedKeyId, SkippedMessageKey>>,
}

impl EphemeralStore {
    /// Creates a new empty ephemeral store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl RatchetStore for EphemeralStore {
    fn save_state(
        &mut self,
        conversation_id: &str,
        state: &RatchetStateData,
    ) -> Result<(), StoreError> {
        self.states.insert(conversation_id.to_string(), state.clone());
        Ok(())
    }

    fn load_state(&self, conversation_id: &str) -> Result<RatchetStateData, StoreError> {
        self.states
            .get(conversation_id)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(conversation_id.to_string()))
    }

    fn exists(&self, conversation_id: &str) -> Result<bool, StoreError> {
        Ok(self.states.contains_key(conversation_id))
    }

    fn delete(&mut self, conversation_id: &str) -> Result<(), StoreError> {
        self.states.remove(conversation_id);
        self.skipped_keys.remove(conversation_id);
        Ok(())
    }

    fn get_skipped_key(
        &self,
        conversation_id: &str,
        id: &SkippedKeyId,
    ) -> Result<Option<crate::types::MessageKey>, StoreError> {
        Ok(self
            .skipped_keys
            .get(conversation_id)
            .and_then(|keys| keys.get(id))
            .map(|sk| sk.message_key))
    }

    fn add_skipped_key(
        &mut self,
        conversation_id: &str,
        key: SkippedMessageKey,
    ) -> Result<(), StoreError> {
        self.skipped_keys
            .entry(conversation_id.to_string())
            .or_default()
            .insert(key.id.clone(), key);
        Ok(())
    }

    fn remove_skipped_key(
        &mut self,
        conversation_id: &str,
        id: &SkippedKeyId,
    ) -> Result<(), StoreError> {
        if let Some(keys) = self.skipped_keys.get_mut(conversation_id) {
            keys.remove(id);
        }
        Ok(())
    }

    fn get_all_skipped_keys(
        &self,
        conversation_id: &str,
    ) -> Result<Vec<SkippedMessageKey>, StoreError> {
        Ok(self
            .skipped_keys
            .get(conversation_id)
            .map(|keys| keys.values().cloned().collect())
            .unwrap_or_default())
    }

    fn clear_skipped_keys(&mut self, conversation_id: &str) -> Result<(), StoreError> {
        self.skipped_keys.remove(conversation_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::InstallationKeyPair;

    fn create_test_state() -> RatchetStateData {
        RatchetStateData {
            root_key: [0x42; 32],
            sending_chain: Some([0x01; 32]),
            receiving_chain: None,
            dh_self: InstallationKeyPair::generate(),
            dh_remote: Some([0x02; 32]),
            msg_send: 0,
            msg_recv: 0,
            prev_chain_len: 0,
        }
    }

    #[test]
    fn test_save_and_load() {
        let mut store = EphemeralStore::new();
        let state = create_test_state();

        store.save_state("conv1", &state).unwrap();
        let loaded = store.load_state("conv1").unwrap();

        assert_eq!(state.root_key, loaded.root_key);
        assert_eq!(state.msg_send, loaded.msg_send);
    }

    #[test]
    fn test_exists() {
        let mut store = EphemeralStore::new();
        let state = create_test_state();

        assert!(!store.exists("conv1").unwrap());
        store.save_state("conv1", &state).unwrap();
        assert!(store.exists("conv1").unwrap());
    }

    #[test]
    fn test_skipped_keys() {
        let mut store = EphemeralStore::new();
        let state = create_test_state();
        store.save_state("conv1", &state).unwrap();

        let id = SkippedKeyId {
            public_key: [0x01; 32],
            msg_num: 5,
        };
        let key = SkippedMessageKey {
            id: id.clone(),
            message_key: [0xAB; 32],
        };

        // Add key
        store.add_skipped_key("conv1", key.clone()).unwrap();
        assert_eq!(
            store.get_skipped_key("conv1", &id).unwrap(),
            Some([0xAB; 32])
        );

        // Remove key
        store.remove_skipped_key("conv1", &id).unwrap();
        assert_eq!(store.get_skipped_key("conv1", &id).unwrap(), None);
    }
}
