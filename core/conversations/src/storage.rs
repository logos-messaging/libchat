//! Chat-specific storage implementation.

mod migrations;
mod types;

use storage::{RusqliteError, SqliteDb, StorageConfig, StorageError, params};
use zeroize::Zeroize;

use crate::{identity::Identity, storage::types::IdentityRecord};

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
}
