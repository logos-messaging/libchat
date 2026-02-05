//! Chat-specific storage implementation.

use std::collections::HashMap;

use storage::{RusqliteError, SqliteDb, StorageError, params};
use x25519_dalek::StaticSecret;

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

    /// Checks if an identity exists.
    pub fn has_identity(&self) -> Result<bool, StorageError> {
        let count: i64 =
            self.db
                .connection()
                .query_row("SELECT COUNT(*) FROM identity", [], |row| row.get(0))?;
        Ok(count > 0)
    }

    // ==================== Inbox Key Operations ====================

    /// Saves an inbox ephemeral key.
    pub fn save_inbox_key(
        &mut self,
        public_key_hex: &str,
        secret: &StaticSecret,
    ) -> Result<(), StorageError> {
        self.db.connection().execute(
            "INSERT OR REPLACE INTO inbox_keys (public_key_hex, secret_key) VALUES (?1, ?2)",
            params![public_key_hex, secret.to_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Loads an inbox ephemeral key by its public key hex.
    pub fn load_inbox_key(
        &self,
        public_key_hex: &str,
    ) -> Result<Option<StaticSecret>, StorageError> {
        let mut stmt = self
            .db
            .connection()
            .prepare("SELECT secret_key FROM inbox_keys WHERE public_key_hex = ?1")?;

        let result = stmt.query_row(params![public_key_hex], |row| {
            let secret_key: Vec<u8> = row.get(0)?;
            Ok(secret_key)
        });

        match result {
            Ok(secret_key) => {
                let bytes: [u8; 32] = secret_key
                    .try_into()
                    .map_err(|_| StorageError::InvalidData("Invalid secret key length".into()))?;
                Ok(Some(StaticSecret::from(bytes)))
            }
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Loads all inbox ephemeral keys.
    pub fn load_all_inbox_keys(&self) -> Result<HashMap<String, StaticSecret>, StorageError> {
        let mut stmt = self
            .db
            .connection()
            .prepare("SELECT public_key_hex, secret_key FROM inbox_keys")?;

        let rows = stmt.query_map([], |row| {
            let public_key_hex: String = row.get(0)?;
            let secret_key: Vec<u8> = row.get(1)?;
            Ok((public_key_hex, secret_key))
        })?;

        let mut keys = HashMap::new();
        for row in rows {
            let (public_key_hex, secret_key) = row?;
            let bytes: [u8; 32] = secret_key
                .try_into()
                .map_err(|_| StorageError::InvalidData("Invalid secret key length".into()))?;
            keys.insert(public_key_hex, StaticSecret::from(bytes));
        }

        Ok(keys)
    }

    /// Deletes an inbox ephemeral key (after it's been used).
    pub fn delete_inbox_key(&mut self, public_key_hex: &str) -> Result<(), StorageError> {
        self.db.connection().execute(
            "DELETE FROM inbox_keys WHERE public_key_hex = ?1",
            params![public_key_hex],
        )?;
        Ok(())
    }

    // ==================== Chat Operations ====================

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

    /// Loads a chat record by ID.
    pub fn load_chat(&self, chat_id: &str) -> Result<Option<ChatRecord>, StorageError> {
        let mut stmt = self.db.connection().prepare(
            "SELECT chat_id, chat_type, remote_public_key, remote_address, created_at
             FROM chats WHERE chat_id = ?1",
        )?;

        let result = stmt.query_row(params![chat_id], |row| {
            let remote_public_key: Option<Vec<u8>> = row.get(2)?;
            Ok(ChatRecord {
                chat_id: row.get(0)?,
                chat_type: row.get(1)?,
                remote_public_key: remote_public_key.and_then(|v| v.try_into().ok()),
                remote_address: row.get(3)?,
                created_at: row.get(4)?,
            })
        });

        match result {
            Ok(record) => Ok(Some(record)),
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Loads all chat records.
    pub fn load_all_chats(&self) -> Result<Vec<ChatRecord>, StorageError> {
        let mut stmt = self.db.connection().prepare(
            "SELECT chat_id, chat_type, remote_public_key, remote_address, created_at FROM chats",
        )?;

        let rows = stmt.query_map([], |row| {
            let remote_public_key: Option<Vec<u8>> = row.get(2)?;
            Ok(ChatRecord {
                chat_id: row.get(0)?,
                chat_type: row.get(1)?,
                remote_public_key: remote_public_key.and_then(|v| v.try_into().ok()),
                remote_address: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;

        let mut chats = Vec::new();
        for row in rows {
            chats.push(row?);
        }

        Ok(chats)
    }

    /// Deletes a chat record.
    pub fn delete_chat(&mut self, chat_id: &str) -> Result<(), StorageError> {
        self.db
            .connection()
            .execute("DELETE FROM chats WHERE chat_id = ?1", params![chat_id])?;
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

    /// Checks if a chat exists.
    pub fn chat_exists(&self, chat_id: &str) -> Result<bool, StorageError> {
        let count: i64 = self.db.connection().query_row(
            "SELECT COUNT(*) FROM chats WHERE chat_id = ?1",
            params![chat_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_roundtrip() {
        let mut storage = ChatStorage::in_memory().unwrap();

        // Initially no identity
        assert!(!storage.has_identity().unwrap());
        assert!(storage.load_identity().unwrap().is_none());

        // Save identity
        let identity = Identity::new();
        let address = identity.address();
        storage.save_identity(&identity).unwrap();

        // Load identity
        assert!(storage.has_identity().unwrap());
        let loaded = storage.load_identity().unwrap().unwrap();
        assert_eq!(loaded.address(), address);
    }

    #[test]
    fn test_inbox_key_roundtrip() {
        let mut storage = ChatStorage::in_memory().unwrap();

        let secret = StaticSecret::random();
        let public_key = x25519_dalek::PublicKey::from(&secret);
        let public_key_hex = hex::encode(public_key.as_bytes());

        // Save key
        storage.save_inbox_key(&public_key_hex, &secret).unwrap();

        // Load key
        let loaded = storage.load_inbox_key(&public_key_hex).unwrap().unwrap();
        assert_eq!(
            x25519_dalek::PublicKey::from(&loaded).as_bytes(),
            public_key.as_bytes()
        );

        // Load all keys
        let all_keys = storage.load_all_inbox_keys().unwrap();
        assert_eq!(all_keys.len(), 1);
        assert!(all_keys.contains_key(&public_key_hex));

        // Delete key
        storage.delete_inbox_key(&public_key_hex).unwrap();
        assert!(storage.load_inbox_key(&public_key_hex).unwrap().is_none());
    }

    #[test]
    fn test_chat_roundtrip() {
        let mut storage = ChatStorage::in_memory().unwrap();

        let remote_key = x25519_dalek::PublicKey::from(&StaticSecret::random());
        let chat = ChatRecord::new_private(
            "chat_123".to_string(),
            remote_key,
            "delivery_addr".to_string(),
        );

        // Save chat
        storage.save_chat(&chat).unwrap();

        // Load chat
        let loaded = storage.load_chat("chat_123").unwrap().unwrap();
        assert_eq!(loaded.chat_id, "chat_123");
        assert_eq!(loaded.chat_type, "private_v1");
        assert_eq!(loaded.remote_address, "delivery_addr");

        // List chats
        let ids = storage.list_chat_ids().unwrap();
        assert_eq!(ids, vec!["chat_123"]);

        // Delete chat
        storage.delete_chat("chat_123").unwrap();
        assert!(!storage.chat_exists("chat_123").unwrap());
    }
}
