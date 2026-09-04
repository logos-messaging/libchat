//! Shared storage layer for libchat.
//!
//! This crate provides a common storage abstraction that can be used by
//! multiple crates in the libchat workspace (conversations, etc.).
//!
//! The storage implementation is handled by other crates.

mod errors;
mod kv;
#[cfg(feature = "test-support")]
mod kv_contract;
mod store;

pub use errors::StorageError;
pub use kv::{KvPair, KvStore, KvTransaction, KvTx, Namespace, Scope, ScopedKvStore};
#[cfg(feature = "test-support")]
pub use kv_contract::assert_kv_contract;
pub use store::{
    ClientStore, ConversationKind, ConversationMeta, ConversationStore, DelegateRecord,
    IdentityStore, Store,
};
