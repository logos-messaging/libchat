use std::collections::HashMap;

use storage::{
    // TODO: (P4) Importable crates need to be prefixed with a project name to avoid conflicts
    ConversationMeta,
    ConversationStore,
    EphemeralKeyStore,
    IdentityStore,
    RatchetStore,
};

/// An Test focused StorageService which holds data in a hashmap
pub struct MemStore {
    convos: HashMap<String, ConversationMeta>,
}

impl MemStore {
    pub fn new() -> Self {
        Self {
            convos: HashMap::new(),
        }
    }
}

impl ConversationStore for MemStore {
    fn save_conversation(
        &mut self,
        meta: &storage::ConversationMeta,
    ) -> Result<(), storage::StorageError> {
        self.convos
            .insert(meta.local_convo_id.clone(), meta.clone());
        Ok(())
    }

    fn load_conversation(
        &self,
        local_convo_id: &str,
    ) -> Result<Option<storage::ConversationMeta>, storage::StorageError> {
        let a = self.convos.get(local_convo_id).cloned();
        Ok(a)
    }

    fn remove_conversation(&mut self, _local_convo_id: &str) -> Result<(), storage::StorageError> {
        todo!()
    }

    fn load_conversations(&self) -> Result<Vec<storage::ConversationMeta>, storage::StorageError> {
        Ok(self.convos.values().cloned().collect())
    }

    fn has_conversation(&self, local_convo_id: &str) -> Result<bool, storage::StorageError> {
        Ok(self.convos.contains_key(local_convo_id))
    }
}

impl IdentityStore for MemStore {
    fn load_identity(&self) -> Result<Option<crypto::Identity>, storage::StorageError> {
        // todo!()
        Ok(None)
    }

    fn save_identity(&mut self, _identity: &crypto::Identity) -> Result<(), storage::StorageError> {
        // todo!()
        Ok(())
    }
}

impl EphemeralKeyStore for MemStore {
    fn save_ephemeral_key(
        &mut self,
        _public_key_hex: &str,
        _private_key: &crypto::PrivateKey,
    ) -> Result<(), storage::StorageError> {
        todo!()
    }

    fn load_ephemeral_key(
        &self,
        _public_key_hex: &str,
    ) -> Result<Option<crypto::PrivateKey>, storage::StorageError> {
        todo!()
    }

    fn remove_ephemeral_key(&mut self, _public_key_hex: &str) -> Result<(), storage::StorageError> {
        todo!()
    }
}

impl RatchetStore for MemStore {
    fn save_ratchet_state(
        &mut self,
        _conversation_id: &str,
        _state: &storage::RatchetStateRecord,
        _skipped_keys: &[storage::SkippedKeyRecord],
    ) -> Result<(), storage::StorageError> {
        todo!()
    }

    fn load_ratchet_state(
        &self,
        _conversation_id: &str,
    ) -> Result<storage::RatchetStateRecord, storage::StorageError> {
        todo!()
    }

    fn load_skipped_keys(
        &self,
        _conversation_id: &str,
    ) -> Result<Vec<storage::SkippedKeyRecord>, storage::StorageError> {
        todo!()
    }

    fn has_ratchet_state(&self, _conversation_id: &str) -> Result<bool, storage::StorageError> {
        todo!()
    }

    fn delete_ratchet_state(
        &mut self,
        _conversation_id: &str,
    ) -> Result<(), storage::StorageError> {
        todo!()
    }

    fn cleanup_old_skipped_keys(
        &mut self,
        _max_age_secs: i64,
    ) -> Result<usize, storage::StorageError> {
        todo!()
    }
}
