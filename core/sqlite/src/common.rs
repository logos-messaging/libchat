//! SQLite storage backend.

use rusqlite::{Connection, Row, Transaction};
use std::path::Path;
use storage::StorageError;

use crate::errors::SqliteError;

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

pub struct DbConn(rusqlite::Connection);
impl DbConn {
    fn map_err(e: rusqlite::Error) -> StorageError {
        StorageError::Database(e.to_string())
    }
    pub fn prepare(&self, sql: &str) -> Result<rusqlite::Statement<'_>, StorageError> {
        self.0.prepare(sql).map_err(Self::map_err)
    }

    pub fn transaction(&mut self) -> Result<Transaction<'_>, StorageError> {
        self.0.transaction().map_err(Self::map_err)
    }

    pub fn execute(&self, sql: &str, params: impl rusqlite::Params) -> Result<usize, StorageError> {
        self.0.execute(sql, params).map_err(Self::map_err)
    }

    pub fn execute_batch(&self, sql: &str) -> Result<(), StorageError> {
        self.0.execute_batch(sql).map_err(Self::map_err)
    }

    pub fn query_row<T, F>(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
        f: F,
    ) -> Result<T, StorageError>
    where
        F: FnOnce(&Row) -> Result<T, rusqlite::Error>,
    {
        self.0.query_row(sql, params, f).map_err(Self::map_err)
    }
}

/// SQLite database wrapper.
///
/// This provides the core database connection and can be shared
/// across different domain-specific storage implementations.
pub struct SqliteDb {
    conn: DbConn,
}

impl SqliteDb {
    /// Creates a new SQLite database with the given configuration.
    pub fn new(config: StorageConfig) -> Result<Self, SqliteError> {
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

        Ok(Self { conn: DbConn(conn) })
    }

    /// Opens an existing database file.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, SqliteError> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(Self { conn: DbConn(conn) })
    }

    /// Creates an in-memory database (useful for testing).
    pub fn in_memory() -> Result<Self, SqliteError> {
        Self::new(StorageConfig::InMemory)
    }

    pub fn sqlcipher(path: String, key: String) -> Result<Self, SqliteError> {
        Self::new(StorageConfig::Encrypted { path, key })
    }

    /// Returns a reference to the underlying connection.
    ///
    /// Use this for domain-specific storage operations.
    pub fn connection(&self) -> &DbConn {
        &self.conn
    }

    /// Returns a mutable reference to the underlying connection.
    ///
    /// Use this for operations that require mutable access, such as transactions.
    pub fn connection_mut(&mut self) -> &mut DbConn {
        &mut self.conn
    }

    /// Begins a transaction.
    pub fn transaction(&mut self) -> Result<rusqlite::Transaction<'_>, SqliteError> {
        Ok(self.conn.transaction()?)
    }
}
