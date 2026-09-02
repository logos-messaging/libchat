use crate::StorageError;

/// A key and the value stored under it.
pub type KvPair = (Vec<u8>, Vec<u8>);

/// The name a protocol keeps its state under; the substrate stores it and never reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Namespace(&'static str);

impl Namespace {
    pub const fn new(name: &'static str) -> Self {
        Self(name)
    }

    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

/// Where a value lives: the owning protocol, and the conversation when the state belongs to one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scope<'a> {
    pub ns: Namespace,
    /// Never empty; protocol-level state has no instance.
    pub instance: Option<&'a str>,
}

/// Byte values addressed by a scope and a key.
///
/// A bare verb commits on its own; `begin` groups several into one transaction. One transaction
/// is open at a time, and while it is the store answers through it alone: a bare verb is an error.
pub trait KvStore {
    fn get(&self, scope: &Scope, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    fn put(&self, scope: &Scope, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    fn delete(&self, scope: &Scope, key: &[u8]) -> Result<(), StorageError>;

    /// Every pair under the prefix, in key order.
    fn scan_prefix(&self, scope: &Scope, prefix: &[u8]) -> Result<Vec<KvPair>, StorageError>;

    fn delete_prefix(&self, scope: &Scope, prefix: &[u8]) -> Result<(), StorageError>;

    fn delete_scope(&self, scope: &Scope) -> Result<(), StorageError>;

    /// Drops every scope under a protocol, its conversations included.
    fn delete_namespace(&self, ns: Namespace) -> Result<(), StorageError>;

    /// Opens a transaction; a second one while it is open is an error.
    fn begin(&self) -> Result<Box<dyn KvTx + '_>, StorageError>;
}

/// The substrate verbs inside one transaction.
///
/// Reads see its own writes. `commit` lands them; dropping it uncommitted discards them.
pub trait KvTx {
    fn get(&self, scope: &Scope, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError>;

    fn put(&self, scope: &Scope, key: &[u8], value: &[u8]) -> Result<(), StorageError>;

    fn delete(&self, scope: &Scope, key: &[u8]) -> Result<(), StorageError>;

    fn scan_prefix(&self, scope: &Scope, prefix: &[u8]) -> Result<Vec<KvPair>, StorageError>;

    fn delete_prefix(&self, scope: &Scope, prefix: &[u8]) -> Result<(), StorageError>;

    fn delete_scope(&self, scope: &Scope) -> Result<(), StorageError>;

    /// Drops every scope under a protocol, its conversations included.
    fn delete_namespace(&self, ns: Namespace) -> Result<(), StorageError>;

    fn commit(self: Box<Self>) -> Result<(), StorageError>;
}

/// A transaction over the substrate.
pub struct KvTransaction<'a> {
    tx: Box<dyn KvTx + 'a>,
}

impl<'a> KvTransaction<'a> {
    pub fn begin<S: KvStore>(store: &'a S) -> Result<Self, StorageError> {
        Ok(Self { tx: store.begin()? })
    }

    /// Binds a scope to the key verbs for the length of the borrow.
    pub fn scope<'s>(
        &'s self,
        ns: impl Into<Namespace>,
        instance: Option<&'s str>,
    ) -> ScopedKvStore<'s> {
        debug_assert!(
            instance.is_none_or(|instance| !instance.is_empty()),
            "an instance is never empty; protocol-level state has none"
        );
        ScopedKvStore {
            tx: self.tx.as_ref(),
            scope: Scope {
                ns: ns.into(),
                instance,
            },
        }
    }

    pub fn delete_scope(&self, scope: &Scope) -> Result<(), StorageError> {
        self.tx.delete_scope(scope)
    }

    /// Drops every scope under a protocol, its conversations included.
    pub fn delete_namespace(&self, ns: impl Into<Namespace>) -> Result<(), StorageError> {
        self.tx.delete_namespace(ns.into())
    }

    pub fn commit(self) -> Result<(), StorageError> {
        self.tx.commit()
    }
}

/// The key verbs with one scope bound.
#[derive(Clone, Copy)]
pub struct ScopedKvStore<'a> {
    tx: &'a dyn KvTx,
    scope: Scope<'a>,
}

impl<'a> ScopedKvStore<'a> {
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.tx.get(&self.scope, key)
    }

    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        self.tx.put(&self.scope, key, value)
    }

    pub fn delete(&self, key: &[u8]) -> Result<(), StorageError> {
        self.tx.delete(&self.scope, key)
    }

    pub fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<KvPair>, StorageError> {
        self.tx.scan_prefix(&self.scope, prefix)
    }

    pub fn delete_prefix(&self, prefix: &[u8]) -> Result<(), StorageError> {
        self.tx.delete_prefix(&self.scope, prefix)
    }
}
