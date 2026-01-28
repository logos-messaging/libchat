//! Shared storage layer for libchat.
//!
//! This crate provides a common storage abstraction that can be used by
//! multiple crates in the libchat workspace (double-ratchets, conversations, etc.).
//!
//! # Features
//!
//! - `sqlite`: Enable SQLite-based storage
//! - `sqlcipher`: Enable encrypted SQLite storage via SQLCipher

mod error;

#[cfg(feature = "sqlite")]
mod sqlite;

pub use error::StorageError;

#[cfg(feature = "sqlite")]
pub use sqlite::{SqliteDb, StorageConfig};

// Re-export rusqlite types that domain crates will need
#[cfg(feature = "sqlite")]
pub use rusqlite::{params, Transaction, Error as RusqliteError};

/// Trait for types that can be stored and retrieved.
///
/// Implement this trait for domain-specific storage operations.
pub trait Storable: Sized {
    /// The key type used to identify records.
    type Key;
    
    /// The error type returned by storage operations.
    type Error: From<StorageError>;
}

/// Trait for storage backends.
pub trait StorageBackend {
    /// Initialize the storage (e.g., create tables).
    fn init(&self) -> Result<(), StorageError>;
    
    /// Execute a batch of SQL statements (for schema migrations).
    fn execute_batch(&self, sql: &str) -> Result<(), StorageError>;
}
