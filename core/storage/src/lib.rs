//! Shared storage layer for libchat.
//!
//! This crate provides a common storage abstraction that can be used by
//! multiple crates in the libchat workspace (conversations, etc.).
//!
//! The storage implementation is handled by other crates.

mod errors;
mod kv;
mod store;

pub use errors::StorageError;
pub use kv::{KvPair, KvStore, KvTransaction, KvTx, Namespace, Scope, ScopedKvStore};
pub use store::{ChatStore, ConversationKind, ConversationMeta, ConversationStore, IdentityStore};
