//! Chat-specific storage implementation.

use std::collections::HashMap;

use storage::{RusqliteError, SqliteDb, StorageConfig, StorageError, params};
use x25519_dalek::StaticSecret;

use super::types::{ChatRecord, IdentityRecord};
use crate::identity::Identity;

/// Schema for chat storage tables.
/// Note: Ratchet state is stored by double_ratchets::RatchetStorage separately.
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
/// This struct wraps a SqliteDb and provides domain-specific
/// storage operations for chat state (identity, inbox keys, chat metadata).
/// 
/// Note: Ratchet state persistence is delegated to double_ratchets::RatchetStorage.
pub struct ChatStorage {
    db: SqliteDb,
}

impl ChatStorage {
    /// Creates a new ChatStorage with the given configuration.
    pub fn new(config: StorageConfig) -> Result<Self, StorageError> {
        let db = SqliteDb::new(config)?;
        Self::run_migration(db)
    }

    /// Creates an in-memory storage (useful for testing).
    pub fn in_memory() -> Result<Self, StorageError> {
        Self::new(StorageConfig::InMemory)
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

    // ==================== Inbox Key Operations ====================

    /// Saves an inbox ephemeral key.
    pub fn save_inbox_key(
        &mut self,
        public_key_hex: &str,
        secret: &StaticSecret,
    ) -> Result<(), StorageError> {
        self.db.connection().execute(
            "INSERT OR REPLACE INTO inbox_keys (public_key_hex, secret_key) VALUES (?1, ?2)",
            params![public_key_hex, secret.as_bytes().as_slice()],
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

    /// Deletes an inbox ephemeral key (after it has been used).
    pub fn delete_inbox_key(&mut self, public_key_hex: &str) -> Result<(), StorageError> {
        self.db.connection().execute(
            "DELETE FROM inbox_keys WHERE public_key_hex = ?1",
            params![public_key_hex],
        )?;
        Ok(())
    }

    // ==================== Chat Metadata Operations ====================

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
            let chat_id: String = row.get(0)?;
            let chat_type: String = row.get(1)?;
            let remote_public_key: Option<Vec<u8>> = row.get(2)?;
            let remote_address: String = row.get(3)?;
            let created_at: i64 = row.get(4)?;
            Ok((
                chat_id,
                chat_type,
                remote_public_key,
                remote_address,
                created_at,
            ))
        });

        match result {
            Ok((chat_id, chat_type, remote_public_key, remote_address, created_at)) => {
                let remote_public_key = remote_public_key.map(|bytes| {
                    let arr: [u8; 32] = bytes.try_into().expect("Invalid key length");
                    arr
                });
                Ok(Some(ChatRecord {
                    chat_id,
                    chat_type,
                    remote_public_key,
                    remote_address,
                    created_at,
                }))
            }
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
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

    /// Checks if a chat exists in storage.
    pub fn chat_exists(&self, chat_id: &str) -> Result<bool, StorageError> {
        let mut stmt = self
            .db
            .connection()
            .prepare("SELECT 1 FROM chats WHERE chat_id = ?1")?;

        let exists = stmt.exists(params![chat_id])?;
        Ok(exists)
    }

    /// Deletes a chat record.
    /// Note: Ratchet state must be deleted separately via RatchetStorage.
    pub fn delete_chat(&mut self, chat_id: &str) -> Result<(), StorageError> {
        self.db
            .connection()
            .execute("DELETE FROM chats WHERE chat_id = ?1", params![chat_id])?;
        Ok(())
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
