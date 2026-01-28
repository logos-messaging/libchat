//! SQLite storage backend.

use rusqlite::Connection;
use std::path::Path;

use crate::{StorageBackend, StorageError};

/// Configuration for SQLite storage.
#[derive(Debug, Clone)]
pub enum StorageConfig {
    /// In-memory database (for testing).
    InMemory,
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

    /// Returns a mutable reference to the underlying connection.
    ///
    /// Use this for operations requiring a transaction.
    pub fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Begins a transaction.
    pub fn transaction(&mut self) -> Result<rusqlite::Transaction<'_>, StorageError> {
        Ok(self.conn.transaction()?)
    }

    /// Checks if a table exists.
    pub fn table_exists(&self, table_name: &str) -> Result<bool, StorageError> {
        let count: i32 = self.conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            [table_name],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }
}

impl StorageBackend for SqliteDb {
    fn init(&self) -> Result<(), StorageError> {
        // Base initialization is done in new()
        Ok(())
    }

    fn execute_batch(&self, sql: &str) -> Result<(), StorageError> {
        self.conn.execute_batch(sql)?;
        Ok(())
    }
}
