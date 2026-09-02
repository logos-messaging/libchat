//! Chat-specific SQLite storage implementation.

mod common;
mod errors;
mod kv;
mod migrations;
mod types;

use crypto::Identity;
use rusqlite::params;
use storage::{ConversationKind, ConversationMeta, ConversationStore, IdentityStore, StorageError};
use zeroize::Zeroize;

use crate::{
    common::SqliteDb,
    errors::{invalid_blob_length, map_optional_row, map_rusqlite_error},
    types::IdentityRecord,
};

pub use common::StorageConfig;

/// Chat-specific storage operations.
///
/// This struct wraps a SqliteDb and provides domain-specific
/// storage operations for chat state (identity, chat metadata).
pub struct SqliteStore {
    db: SqliteDb,
}

impl SqliteStore {
    /// Creates a new SqliteStore with the given configuration.
    pub fn new(config: StorageConfig) -> Result<Self, StorageError> {
        let db = SqliteDb::new(config)?;
        Self::run_migrations(db)
    }

    pub fn in_memory() -> Self {
        Self::new(StorageConfig::InMemory).unwrap()
    }

    /// Applies all migrations and returns the storage instance.
    fn run_migrations(mut db: SqliteDb) -> Result<Self, StorageError> {
        migrations::apply_migrations(db.connection_mut())?;
        Ok(Self { db })
    }
}

impl IdentityStore for SqliteStore {
    /// Loads the identity if it exists.
    ///
    /// Note: Secret key bytes are zeroized after being copied into IdentityRecord,
    /// which handles its own zeroization via ZeroizeOnDrop.
    fn load_identity(&self) -> Result<Option<Identity>, StorageError> {
        let mut stmt = self
            .db
            .connection()
            .prepare("SELECT name, secret_key FROM identity WHERE id = 1")
            .map_err(map_rusqlite_error)?;

        let result = stmt.query_row([], |row| {
            let name: String = row.get(0)?;
            let secret_key: Vec<u8> = row.get(1)?;
            Ok((name, secret_key))
        });

        match map_optional_row(result)? {
            Some((name, mut secret_key_vec)) => {
                let bytes: Result<[u8; 32], _> = secret_key_vec.as_slice().try_into();
                let bytes = match bytes {
                    Ok(b) => b,
                    Err(_) => {
                        secret_key_vec.zeroize();
                        return Err(invalid_blob_length(
                            "identity.secret_key",
                            32,
                            secret_key_vec.len(),
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
            None => Ok(None),
        }
    }

    /// Saves the identity (secret key).
    ///
    /// Note: The secret key bytes are explicitly zeroized after use to minimize
    /// the time sensitive data remains in stack memory.
    fn save_identity(&mut self, identity: &Identity) -> Result<(), StorageError> {
        let mut secret_bytes = identity.secret().DANGER_to_bytes();
        let result = self
            .db
            .connection()
            .execute(
                "INSERT OR REPLACE INTO identity (id, name, secret_key) VALUES (1, ?1, ?2)",
                params![identity.get_name(), secret_bytes.as_slice()],
            )
            .map_err(map_rusqlite_error);
        secret_bytes.zeroize();
        result?;
        Ok(())
    }
}

impl ConversationStore for SqliteStore {
    /// Saves conversation metadata.
    fn save_conversation(&mut self, meta: &ConversationMeta) -> Result<(), StorageError> {
        self.db
            .connection()
            .execute(
                "INSERT OR REPLACE INTO conversations (local_convo_id, convo_type) VALUES (?1, ?2)",
                params![meta.local_convo_id, meta.kind.as_str()],
            )
            .map_err(map_rusqlite_error)?;
        Ok(())
    }

    /// Loads a single conversation record by its local ID.
    fn load_conversation(
        &self,
        local_convo_id: &str,
    ) -> Result<Option<ConversationMeta>, StorageError> {
        let mut stmt = self
            .db
            .connection()
            .prepare(
                "SELECT local_convo_id, convo_type FROM conversations WHERE local_convo_id = ?1",
            )
            .map_err(map_rusqlite_error)?;

        let result = stmt.query_row(params![local_convo_id], |row| {
            let local_convo_id: String = row.get(0)?;
            let convo_type: String = row.get(1)?;
            Ok(ConversationMeta {
                local_convo_id,
                kind: ConversationKind::from(convo_type.as_str()),
            })
        });

        map_optional_row(result)
    }

    /// Removes a conversation by its local ID.
    fn remove_conversation(&mut self, local_convo_id: &str) -> Result<(), StorageError> {
        self.db
            .connection()
            .execute(
                "DELETE FROM conversations WHERE local_convo_id = ?1",
                params![local_convo_id],
            )
            .map_err(map_rusqlite_error)?;
        Ok(())
    }

    /// Loads all conversation records.
    fn load_conversations(&self) -> Result<Vec<ConversationMeta>, StorageError> {
        let mut stmt = self
            .db
            .connection()
            .prepare("SELECT local_convo_id, convo_type FROM conversations")
            .map_err(map_rusqlite_error)?;

        let records = stmt
            .query_map([], |row| {
                let local_convo_id: String = row.get(0)?;
                let convo_type: String = row.get(1)?;
                Ok(ConversationMeta {
                    local_convo_id,
                    kind: ConversationKind::from(convo_type.as_str()),
                })
            })
            .map_err(map_rusqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_rusqlite_error)?;

        Ok(records)
    }

    /// Checks if a conversation exists by its local ID.
    fn has_conversation(&self, local_convo_id: &str) -> Result<bool, StorageError> {
        let exists: bool = self
            .db
            .connection()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM conversations WHERE local_convo_id = ?1)",
                params![local_convo_id],
                |row| row.get(0),
            )
            .map_err(map_rusqlite_error)?;
        Ok(exists)
    }
}

#[cfg(test)]
mod tests {
    use storage::{ConversationKind, ConversationMeta, ConversationStore, IdentityStore};

    use super::*;

    #[test]
    fn test_identity_roundtrip() {
        let mut storage = SqliteStore::new(StorageConfig::InMemory).unwrap();

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
    fn test_conversation_roundtrip() {
        let mut storage = SqliteStore::new(StorageConfig::InMemory).unwrap();

        // Initially empty
        let convos = storage.load_conversations().unwrap();
        assert!(convos.is_empty());

        // Save conversations
        storage
            .save_conversation(&ConversationMeta {
                local_convo_id: "local_1".into(),
                kind: ConversationKind::GroupV1,
            })
            .unwrap();
        storage
            .save_conversation(&ConversationMeta {
                local_convo_id: "local_2".into(),
                kind: ConversationKind::DirectV1,
            })
            .unwrap();

        let convos = storage.load_conversations().unwrap();
        assert_eq!(convos.len(), 2);

        // Remove one
        storage.remove_conversation("local_1").unwrap();
        let convos = storage.load_conversations().unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].local_convo_id, "local_2");
        assert_eq!(convos[0].kind.as_str(), "direct_v1");
    }
}
