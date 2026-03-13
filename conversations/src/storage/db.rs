//! Chat-specific storage implementation.

use storage::{RusqliteError, SqliteDb, StorageConfig, StorageError, params};
use zeroize::Zeroize;

use super::migrations;
use super::types::{ConversationRecord, IdentityRecord};
use crate::crypto::PrivateKey;
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
    fn run_migrations(mut db: SqliteDb) -> Result<Self, StorageError> {
        migrations::apply_migrations(db.connection_mut())?;
        Ok(Self { db })
    }

    // ==================== Identity Operations ====================

    /// Saves the identity (secret key).
    ///
    /// Note: The secret key bytes are explicitly zeroized after use to minimize
    /// the time sensitive data remains in stack memory.
    pub fn save_identity(&mut self, identity: &Identity) -> Result<(), StorageError> {
        let mut secret_bytes = identity.secret().DANGER_to_bytes();
        let result = self.db.connection().execute(
            "INSERT OR REPLACE INTO identity (id, name, secret_key) VALUES (1, ?1, ?2)",
            params![identity.get_name(), secret_bytes.as_slice()],
        );
        secret_bytes.zeroize();
        result?;
        Ok(())
    }

    // ==================== Ephemeral Key Operations ====================

    /// Saves an ephemeral key pair to storage.
    pub fn save_ephemeral_key(
        &mut self,
        public_key_hex: &str,
        private_key: &PrivateKey,
    ) -> Result<(), StorageError> {
        let mut secret_bytes = private_key.DANGER_to_bytes();
        let result = self.db.connection().execute(
            "INSERT OR REPLACE INTO ephemeral_keys (public_key_hex, secret_key) VALUES (?1, ?2)",
            params![public_key_hex, secret_bytes.as_slice()],
        );
        secret_bytes.zeroize();
        result?;
        Ok(())
    }

    /// Loads a single ephemeral key by its public key hex.
    pub fn load_ephemeral_key(
        &self,
        public_key_hex: &str,
    ) -> Result<Option<PrivateKey>, StorageError> {
        let mut stmt = self
            .db
            .connection()
            .prepare("SELECT secret_key FROM ephemeral_keys WHERE public_key_hex = ?1")?;

        let result = stmt.query_row(params![public_key_hex], |row| {
            let secret_key: Vec<u8> = row.get(0)?;
            Ok(secret_key)
        });

        match result {
            Ok(mut secret_key_vec) => {
                let bytes: Result<[u8; 32], _> = secret_key_vec.as_slice().try_into();
                let bytes = match bytes {
                    Ok(b) => b,
                    Err(_) => {
                        secret_key_vec.zeroize();
                        return Err(StorageError::InvalidData(
                            "Invalid ephemeral secret key length".into(),
                        ));
                    }
                };
                secret_key_vec.zeroize();
                Ok(Some(PrivateKey::from(bytes)))
            }
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Removes an ephemeral key from storage.
    pub fn remove_ephemeral_key(&mut self, public_key_hex: &str) -> Result<(), StorageError> {
        self.db.connection().execute(
            "DELETE FROM ephemeral_keys WHERE public_key_hex = ?1",
            params![public_key_hex],
        )?;
        Ok(())
    }

    // ==================== Conversation Operations ====================

    /// Saves conversation metadata.
    pub fn save_conversation(
        &mut self,
        local_convo_id: &str,
        remote_convo_id: &str,
        convo_type: &str,
    ) -> Result<(), StorageError> {
        self.db.connection().execute(
            "INSERT OR REPLACE INTO conversations (local_convo_id, remote_convo_id, convo_type) VALUES (?1, ?2, ?3)",
            params![local_convo_id, remote_convo_id, convo_type],
        )?;
        Ok(())
    }

    /// Loads all conversation records.
    pub fn load_conversations(&self) -> Result<Vec<ConversationRecord>, StorageError> {
        let mut stmt = self.db.connection().prepare(
            "SELECT local_convo_id, remote_convo_id, convo_type FROM conversations",
        )?;

        let records = stmt
            .query_map([], |row| {
                Ok(ConversationRecord {
                    local_convo_id: row.get(0)?,
                    remote_convo_id: row.get(1)?,
                    convo_type: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(records)
    }

    /// Removes a conversation by its local ID.
    pub fn remove_conversation(&mut self, local_convo_id: &str) -> Result<(), StorageError> {
        self.db.connection().execute(
            "DELETE FROM conversations WHERE local_convo_id = ?1",
            params![local_convo_id],
        )?;
        Ok(())
    }

    // ==================== Identity Operations (continued) ====================

    /// Loads the identity if it exists.
    ///
    /// Note: Secret key bytes are zeroized after being copied into IdentityRecord,
    /// which handles its own zeroization via ZeroizeOnDrop.
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
            Ok((name, mut secret_key_vec)) => {
                let bytes: Result<[u8; 32], _> = secret_key_vec.as_slice().try_into();
                let bytes = match bytes {
                    Ok(b) => b,
                    Err(_) => {
                        secret_key_vec.zeroize();
                        return Err(StorageError::InvalidData(
                            "Invalid secret key length".into(),
                        ));
                    }
                };
                secret_key_vec.zeroize();
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
    fn test_ephemeral_key_roundtrip() {
        let mut storage = ChatStorage::new(StorageConfig::InMemory).unwrap();

        let key1 = PrivateKey::random();
        let pub1: crate::crypto::PublicKey = (&key1).into();
        let hex1 = hex::encode(pub1.as_bytes());

        // Initially not found
        assert!(storage.load_ephemeral_key(&hex1).unwrap().is_none());

        // Save and load
        storage.save_ephemeral_key(&hex1, &key1).unwrap();
        let loaded = storage.load_ephemeral_key(&hex1).unwrap().unwrap();
        assert_eq!(loaded.DANGER_to_bytes(), key1.DANGER_to_bytes());

        // Remove and verify gone
        storage.remove_ephemeral_key(&hex1).unwrap();
        assert!(storage.load_ephemeral_key(&hex1).unwrap().is_none());
    }

    #[test]
    fn test_conversation_roundtrip() {
        let mut storage = ChatStorage::new(StorageConfig::InMemory).unwrap();

        // Initially empty
        let convos = storage.load_conversations().unwrap();
        assert!(convos.is_empty());

        // Save conversations
        storage
            .save_conversation("local_1", "remote_1", "private_v1")
            .unwrap();
        storage
            .save_conversation("local_2", "remote_2", "private_v1")
            .unwrap();

        let convos = storage.load_conversations().unwrap();
        assert_eq!(convos.len(), 2);

        // Remove one
        storage.remove_conversation("local_1").unwrap();
        let convos = storage.load_conversations().unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].local_convo_id, "local_2");
        assert_eq!(convos[0].remote_convo_id, "remote_2");
        assert_eq!(convos[0].convo_type, "private_v1");
    }
}
