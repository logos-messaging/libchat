//! Chat-specific storage implementation.

use storage::{RusqliteError, SqliteDb, StorageConfig, StorageError, params};
use x25519_dalek::StaticSecret;

use super::migrations;
use super::types::{ChatRecord, IdentityRecord};
use crate::identity::Identity;

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
        Self::run_migrations(db)
    }

    /// Applies all migrations and returns the storage instance.
    fn run_migrations(db: SqliteDb) -> Result<Self, StorageError> {
        migrations::apply_migrations(db.connection())?;
        Ok(Self { db })
    }

    // ==================== Identity Operations ====================

    /// Saves the identity (secret key).
    pub fn save_identity(&mut self, identity: &Identity) -> Result<(), StorageError> {
        self.db.connection().execute(
            "INSERT OR REPLACE INTO identity (id, name, secret_key) VALUES (1, ?1, ?2)",
            params![
                identity.get_name(),
                identity.secret().DANGER_to_bytes().as_slice()
            ],
        )?;
        Ok(())
    }

    /// Loads the identity if it exists.
    pub fn load_identity(&self) -> Result<Option<Identity>, StorageError> {
        let mut stmt = self
            .db
            .connection()
            .prepare("SELECT name, secret_key FROM identity WHERE id = 1")?;

        let result = stmt.query_row([], |row| {
            let name: String = row.get(0)?;
            let secret_key: Vec<u8> = row.get(1)?;
            Ok((name, secret_key))
        });

        match result {
            Ok((name, secret_key)) => {
                let bytes: [u8; 32] = secret_key
                    .try_into()
                    .map_err(|_| StorageError::InvalidData("Invalid secret key length".into()))?;
                let record = IdentityRecord {
                    name,
                    secret_key: bytes,
                };
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

    /// Loads a single inbox ephemeral key by public key hex.
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

    /// Deletes an inbox ephemeral key after it has been used.
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

    /// Finds a chat by remote address.
    /// Returns the chat_id if found, None otherwise.
    #[allow(dead_code)]
    pub fn find_chat_by_remote_address(
        &self,
        remote_address: &str,
    ) -> Result<Option<String>, StorageError> {
        let mut stmt = self
            .db
            .connection()
            .prepare("SELECT chat_id FROM chats WHERE remote_address = ?1 LIMIT 1")?;

        let mut rows = stmt.query(params![remote_address])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
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
        let mut storage = ChatStorage::new(StorageConfig::InMemory).unwrap();

        // Initially no identity
        assert!(storage.load_identity().unwrap().is_none());

        // Save identity
        let identity = Identity::new("default");
        let pubkey = identity.public_key();
        storage.save_identity(&identity).unwrap();

        // Load identity
        let loaded = storage.load_identity().unwrap().unwrap();
        assert_eq!(loaded.public_key(), pubkey);
    }

    #[test]
    fn test_chat_roundtrip() {
        let mut storage = ChatStorage::new(StorageConfig::InMemory).unwrap();

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
