use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    fmt::Debug,
    rc::Rc,
    sync::{Arc, Mutex},
};

use storage::{ConversationMeta, ConversationStore, IdentityStore};
use storage::{EphemeralKeyStore, RatchetStore};

use crate::{
    AccountId, AddressedEnvelope, DeliveryService, RegistrationService,
    utils::{blake2b_hex, hash_size::Testing},
};

#[derive(Debug)]
struct BroadcasterShared<T> {
    /// Per-address message queue; all published messages are appended here.
    messages: VecDeque<T>,
    base_index: usize,
}

impl<T> BroadcasterShared<T> {
    pub fn read(&self, cursor: usize) -> Option<&T> {
        self.messages.get(cursor + self.base_index)
    }

    pub fn tail(&self) -> usize {
        self.messages.len() + self.base_index
    }
}

#[derive(Clone, Debug)]
pub struct LocalBroadcaster {
    shared: Rc<RefCell<BroadcasterShared<AddressedEnvelope>>>,
    cursor: usize,
    subscriptions: HashSet<String>,
    outbound_msgs: Vec<String>,
}

impl LocalBroadcaster {
    pub fn new() -> Self {
        let shared = Rc::new(RefCell::new(BroadcasterShared {
            messages: VecDeque::new(),
            base_index: 0,
        }));

        let cursor = shared.borrow().tail();
        Self {
            shared,
            cursor,
            subscriptions: HashSet::new(),
            outbound_msgs: Vec::new(),
        }
    }

    /// Returns a new consumer that shares the same message store but has its
    /// own independent cursor — it starts from the beginning of each address
    /// queue regardless of what any other consumer has already processed.
    pub fn new_consumer(&self) -> Self {
        let inner = self.shared.clone();
        let cursor = inner.borrow().tail();
        Self {
            shared: inner,
            cursor,
            subscriptions: HashSet::new(),
            outbound_msgs: Vec::new(),
        }
    }

    /// Pulls all messages this consumer has not yet seen on `address`,
    /// applying any registered filter.  Advances the cursor so the same
    /// messages are not returned again.
    pub fn poll(&mut self) -> Option<Vec<u8>> {
        loop {
            let next = self.cursor;
            match self.shared.borrow().read(next) {
                None => return None,
                Some(ae) => {
                    self.cursor = next + 1;
                    if self.subscriptions.contains(ae.delivery_address.as_str())
                        && self.is_inbound(ae)
                    {
                        return Some(ae.data.clone());
                    }
                }
            }
        }
    }

    fn msg_id(msg: &AddressedEnvelope) -> String {
        blake2b_hex::<Testing>(&[msg.data.as_slice()])
    }

    fn is_inbound(&self, msg: &AddressedEnvelope) -> bool {
        let mid = Self::msg_id(msg);
        !self.outbound_msgs.contains(&mid)
    }
}

impl DeliveryService for LocalBroadcaster {
    type Error = String;

    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), Self::Error> {
        self.outbound_msgs.push(Self::msg_id(&envelope));
        self.shared.borrow_mut().messages.push_back(envelope);

        Ok(())
    }

    fn subscribe(&mut self, delivery_address: &str) -> Result<(), Self::Error> {
        // Strict temporal ordering of subscriptions is not enforced.
        // Subscruptions are evaluated on polling, not when the message is published
        self.subscriptions.insert(delivery_address.to_string());
        Ok(())
    }
}

/// A Contact Registry used for Tests.
/// This implementation stores bundle bytes and then returns them when
/// retrieved
///

#[derive(Clone)]
pub struct EphemeralRegistry {
    registry: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl EphemeralRegistry {
    pub fn new() -> Self {
        Self {
            registry: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Debug for EphemeralRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let registry = self.registry.lock().unwrap();
        let truncated: Vec<(&String, String)> = registry
            .iter()
            .map(|(k, v)| {
                let hex = if v.len() <= 8 {
                    hex::encode(v)
                } else {
                    format!(
                        "{}..{}",
                        hex::encode(&v[..4]),
                        hex::encode(&v[v.len() - 4..])
                    )
                };
                (k, hex)
            })
            .collect();
        f.debug_struct("EphemeralRegistry")
            .field("registry", &truncated)
            .finish()
    }
}

impl RegistrationService for EphemeralRegistry {
    type Error = String;
    fn register(&mut self, identity: &str, key_bundle: Vec<u8>) -> Result<(), Self::Error> {
        self.registry
            .lock()
            .unwrap()
            .insert(identity.to_string(), key_bundle);
        Ok(())
    }

    fn retrieve(&self, identity: &AccountId) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self
            .registry
            .lock()
            .unwrap()
            .get(identity.as_str())
            .cloned())
    }
}

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
