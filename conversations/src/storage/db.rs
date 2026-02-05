//! Chat-specific storage implementation.

use storage::{RusqliteError, SqliteDb, StorageError, params};

use super::types::{ChatRecord, IdentityRecord};
use crate::identity::Identity;

/// Schema for chat storage tables.
const CHAT_SCHEMA: &str = "
    -- Identity table (single row)
    CREATE TABLE IF NOT EXISTS identity (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        secret_key BLOB NOT NULL
    );

    -- Inbox ephemeral keys for handshakes
    CREATE TABLE IF NOT EXISTS inbox_keys (
        public_key_hex TEXT PRIMARY KEY,
        secret_key BLOB NOT NULL,
        created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
    );

    -- Chat metadata
    CREATE TABLE IF NOT EXISTS chats (
        chat_id TEXT PRIMARY KEY,
        chat_type TEXT NOT NULL,
        remote_public_key BLOB,
        remote_address TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_chats_type ON chats(chat_type);
";

/// Chat-specific storage operations.
///
/// This struct wraps a `SqliteDb` and provides domain-specific
/// storage operations for chat state.
pub struct ChatStorage {
    db: SqliteDb,
}

impl ChatStorage {
    /// Opens an existing encrypted database file.
    pub fn new(path: &str, key: &str) -> Result<Self, StorageError> {
        let db = SqliteDb::sqlcipher(path.to_string(), key.to_string())?;
        Self::run_migration(db)
    }

    /// Creates an in-memory storage (useful for testing).
    pub fn in_memory() -> Result<Self, StorageError> {
        let db = SqliteDb::in_memory()?;
        Self::run_migration(db)
    }

    /// Opens an unencrypted database file (for development/testing).
    pub fn open(path: &str) -> Result<Self, StorageError> {
        let db = SqliteDb::open(path)?;
        Self::run_migration(db)
    }

    /// Creates a new chat storage with the given database.
    fn run_migration(db: SqliteDb) -> Result<Self, StorageError> {
        db.connection().execute_batch(CHAT_SCHEMA)?;
        Ok(Self { db })
    }

    // ==================== Identity Operations ====================

    /// Saves the identity (secret key).
    pub fn save_identity(&mut self, identity: &Identity) -> Result<(), StorageError> {
        let record = IdentityRecord::from(identity);
        self.db.connection().execute(
            "INSERT OR REPLACE INTO identity (id, secret_key) VALUES (1, ?1)",
            params![record.secret_key.as_slice()],
        )?;
        Ok(())
    }

    /// Loads the identity if it exists.
    pub fn load_identity(&self) -> Result<Option<Identity>, StorageError> {
        let mut stmt = self
            .db
            .connection()
            .prepare("SELECT secret_key FROM identity WHERE id = 1")?;

        let result = stmt.query_row([], |row| {
            let secret_key: Vec<u8> = row.get(0)?;
            Ok(secret_key)
        });

        match result {
            Ok(secret_key) => {
                let bytes: [u8; 32] = secret_key
                    .try_into()
                    .map_err(|_| StorageError::InvalidData("Invalid secret key length".into()))?;
                let record = IdentityRecord { secret_key: bytes };
                Ok(Some(Identity::from(record)))
            }
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Saves a chat record.
    pub fn save_chat(&mut self, chat: &ChatRecord) -> Result<(), StorageError> {
        self.db.connection().execute(
            "INSERT OR REPLACE INTO chats (chat_id, chat_type, remote_public_key, remote_address, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                chat.chat_id,
                chat.chat_type,
                chat.remote_public_key.as_ref().map(|k| k.as_slice()),
                chat.remote_address,
                chat.created_at,
            ],
        )?;
        Ok(())
    }

    /// Lists all chat IDs.
    pub fn list_chat_ids(&self) -> Result<Vec<String>, StorageError> {
        let mut stmt = self.db.connection().prepare("SELECT chat_id FROM chats")?;
        let rows = stmt.query_map([], |row| row.get(0))?;

        let mut ids = Vec::new();
        for row in rows {
            ids.push(row?);
        }

        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_roundtrip() {
        let mut storage = ChatStorage::in_memory().unwrap();

        // Initially no identity
        assert!(storage.load_identity().unwrap().is_none());

        // Save identity
        let identity = Identity::new();
        let address = identity.address();
        storage.save_identity(&identity).unwrap();

        // Load identity
        let loaded = storage.load_identity().unwrap().unwrap();
        assert_eq!(loaded.address(), address);
    }

    #[test]
    fn test_chat_roundtrip() {
        let mut storage = ChatStorage::in_memory().unwrap();

        let secret = x25519_dalek::StaticSecret::random();
        let remote_key = x25519_dalek::PublicKey::from(&secret);
        let chat = ChatRecord::new_private(
            "chat_123".to_string(),
            remote_key,
            "delivery_addr".to_string(),
        );

        // Save chat
        storage.save_chat(&chat).unwrap();

        // List chats
        let ids = storage.list_chat_ids().unwrap();
        assert_eq!(ids, vec!["chat_123"]);
    }
}
