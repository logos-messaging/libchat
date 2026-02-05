//! SQLite storage backend.

use rusqlite::Connection;
use std::path::Path;

use crate::StorageError;

/// Configuration for SQLite storage.
#[derive(Debug, Clone)]
pub enum StorageConfig {
    /// In-memory database (isolated, for simple testing).
    InMemory,
    /// Shared in-memory database with a name (multiple connections share data).
    /// Use this when you need multiple storage instances to share the same in-memory DB.
    SharedInMemory(String),
    /// File-based SQLite database.
    File(String),
    /// SQLCipher encrypted database.
    Encrypted { path: String, key: String },
}

/// SQLite database wrapper.
///
/// This provides the core database connection and can be shared
/// across different domain-specific storage implementations.
pub struct SqliteDb {
    conn: Connection,
}

impl SqliteDb {
    /// Creates a new SQLite database with the given configuration.
    pub fn new(config: StorageConfig) -> Result<Self, StorageError> {
        let conn = match config {
            StorageConfig::InMemory => Connection::open_in_memory()?,
            StorageConfig::SharedInMemory(ref name) => {
                // Use URI mode to create a shared in-memory database
                // Multiple connections with the same name share the same data
                let uri = format!("file:{}?mode=memory&cache=shared", name);
                Connection::open_with_flags(
                    &uri,
                    rusqlite::OpenFlags::SQLITE_OPEN_URI
                        | rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                        | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
                )?
            }
            StorageConfig::File(ref path) => Connection::open(path)?,
            StorageConfig::Encrypted { ref path, ref key } => {
                let conn = Connection::open(path)?;
                conn.pragma_update(None, "key", key)?;
                conn
            }
        };

        // Enable foreign keys
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;

        Ok(Self { conn })
    }

    /// Opens an existing database file.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(Self { conn })
    }

    /// Creates an in-memory database (useful for testing).
    pub fn in_memory() -> Result<Self, StorageError> {
        Self::new(StorageConfig::InMemory)
    }

    pub fn sqlcipher(path: String, key: String) -> Result<Self, StorageError> {
        Self::new(StorageConfig::Encrypted {
            path: path,
            key: key,
        })
    }

    /// Returns a reference to the underlying connection.
    ///
    /// Use this for domain-specific storage operations.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Begins a transaction.
    pub fn transaction(&mut self) -> Result<rusqlite::Transaction<'_>, StorageError> {
        Ok(self.conn.transaction()?)
    }
}
