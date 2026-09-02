//! A store that refuses a write on demand, so a test can see what an operation leaves behind
//! when the write it depends on does not land.

use std::cell::Cell;
use std::rc::Rc;

use components::MemStore;
use crypto::Identity;
use storage::{
    ConversationMeta, ConversationStore, DelegateRecord, IdentityStore, KvPair, KvStore, KvTx,
    Namespace, Scope, StorageError,
};

/// The refusals a [`FaultStore`] produces, switchable while it is in use.
#[derive(Clone, Default)]
pub struct Faults {
    commit: Rc<Cell<bool>>,
    record_delete: Rc<Cell<bool>>,
}

impl Faults {
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh store producing these refusals.
    pub fn store(&self) -> FaultStore {
        FaultStore {
            inner: MemStore::new(),
            faults: self.clone(),
        }
    }

    /// While set, a transaction fails as it lands, with everything it wrote already staged.
    pub fn fail_commit(&self, fail: bool) {
        self.commit.set(fail);
    }

    /// While set, deleting a conversation record fails.
    pub fn fail_record_delete(&self, fail: bool) {
        self.record_delete.set(fail);
    }
}

/// An in-memory store that answers every contract, refusing the writes its [`Faults`] name.
pub struct FaultStore {
    inner: MemStore,
    faults: Faults,
}

impl IdentityStore for FaultStore {
    fn load_identity(&self) -> Result<Option<Identity>, StorageError> {
        self.inner.load_identity()
    }

    fn save_identity(&mut self, identity: &Identity) -> Result<(), StorageError> {
        self.inner.save_identity(identity)
    }

    fn load_delegate(&self) -> Result<Option<DelegateRecord>, StorageError> {
        self.inner.load_delegate()
    }

    fn save_delegate(&mut self, delegate: &DelegateRecord) -> Result<(), StorageError> {
        self.inner.save_delegate(delegate)
    }
}

impl ConversationStore for FaultStore {
    fn save_conversation(&mut self, meta: &ConversationMeta) -> Result<(), StorageError> {
        self.inner.save_conversation(meta)
    }

    fn load_conversation(&self, convo_id: &str) -> Result<Option<ConversationMeta>, StorageError> {
        self.inner.load_conversation(convo_id)
    }

    fn remove_conversation(&mut self, convo_id: &str) -> Result<(), StorageError> {
        if self.faults.record_delete.get() {
            return Err(StorageError::Database("record delete refused".into()));
        }
        self.inner.remove_conversation(convo_id)
    }

    fn load_conversations(&self) -> Result<Vec<ConversationMeta>, StorageError> {
        self.inner.load_conversations()
    }

    fn has_conversation(&self, convo_id: &str) -> Result<bool, StorageError> {
        self.inner.has_conversation(convo_id)
    }
}

impl KvStore for FaultStore {
    fn get(&self, scope: &Scope, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(scope, key)
    }

    fn put(&self, scope: &Scope, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.inner.put(scope, key, value)
    }

    fn delete(&self, scope: &Scope, key: &[u8]) -> Result<(), StorageError> {
        self.inner.delete(scope, key)
    }

    fn scan_prefix(&self, scope: &Scope, prefix: &[u8]) -> Result<Vec<KvPair>, StorageError> {
        self.inner.scan_prefix(scope, prefix)
    }

    fn delete_prefix(&self, scope: &Scope, prefix: &[u8]) -> Result<(), StorageError> {
        self.inner.delete_prefix(scope, prefix)
    }

    fn delete_scope(&self, scope: &Scope) -> Result<(), StorageError> {
        self.inner.delete_scope(scope)
    }

    fn delete_namespace(&self, ns: Namespace) -> Result<(), StorageError> {
        self.inner.delete_namespace(ns)
    }

    fn begin(&self) -> Result<Box<dyn KvTx + '_>, StorageError> {
        Ok(Box::new(FaultTx {
            inner: self.inner.begin()?,
            faults: self.faults.clone(),
        }))
    }
}

struct FaultTx<'a> {
    inner: Box<dyn KvTx + 'a>,
    faults: Faults,
}

impl KvTx for FaultTx<'_> {
    fn get(&self, scope: &Scope, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(scope, key)
    }

    fn put(&self, scope: &Scope, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.inner.put(scope, key, value)
    }

    fn delete(&self, scope: &Scope, key: &[u8]) -> Result<(), StorageError> {
        self.inner.delete(scope, key)
    }

    fn scan_prefix(&self, scope: &Scope, prefix: &[u8]) -> Result<Vec<KvPair>, StorageError> {
        self.inner.scan_prefix(scope, prefix)
    }

    fn delete_prefix(&self, scope: &Scope, prefix: &[u8]) -> Result<(), StorageError> {
        self.inner.delete_prefix(scope, prefix)
    }

    fn delete_scope(&self, scope: &Scope) -> Result<(), StorageError> {
        self.inner.delete_scope(scope)
    }

    fn delete_namespace(&self, ns: Namespace) -> Result<(), StorageError> {
        self.inner.delete_namespace(ns)
    }

    fn commit(self: Box<Self>) -> Result<(), StorageError> {
        if self.faults.commit.get() {
            return Err(StorageError::Database("commit refused".into()));
        }
        self.inner.commit()
    }
}
