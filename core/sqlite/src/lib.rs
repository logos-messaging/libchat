//! Chat-specific SQLite storage implementation.

mod common;
mod errors;
mod migrations;
mod types;

use std::collections::HashSet;

use crypto::{Identity, PrivateKey};
use rusqlite::{Error as RusqliteError, Transaction, params};
use storage::{
    ConversationKind, ConversationMeta, ConversationStore, EphemeralKeyStore, IdentityStore,
    RatchetStateRecord, RatchetStore, SkippedKeyRecord, StorageError,
};
use zeroize::Zeroize;

use crate::{
    common::{SqliteDb, StorageConfig},
    types::IdentityRecord,
};

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

    pub fn in_memory() -> Self {
        Self::new(StorageConfig::InMemory).unwrap()
    }

    /// Applies all migrations and returns the storage instance.
    fn run_migrations(mut db: SqliteDb) -> Result<Self, StorageError> {
        migrations::apply_migrations(db.connection_mut())?;
        Ok(Self { db })
    }
}

impl IdentityStore for ChatStorage {
    /// Loads the identity if it exists.
    ///
    /// Note: Secret key bytes are zeroized after being copied into IdentityRecord,
    /// which handles its own zeroization via ZeroizeOnDrop.
    fn load_identity(&self) -> Result<Option<Identity>, StorageError> {
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

    /// Saves the identity (secret key).
    ///
    /// Note: The secret key bytes are explicitly zeroized after use to minimize
    /// the time sensitive data remains in stack memory.
    fn save_identity(&mut self, identity: &Identity) -> Result<(), StorageError> {
        let mut secret_bytes = identity.secret().DANGER_to_bytes();
        let result = self.db.connection().execute(
            "INSERT OR REPLACE INTO identity (id, name, secret_key) VALUES (1, ?1, ?2)",
            params![identity.get_name(), secret_bytes.as_slice()],
        );
        secret_bytes.zeroize();
        result?;
        Ok(())
    }
}

impl EphemeralKeyStore for ChatStorage {
    /// Saves an ephemeral key pair to storage.
    fn save_ephemeral_key(
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
    fn load_ephemeral_key(&self, public_key_hex: &str) -> Result<Option<PrivateKey>, StorageError> {
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
    fn remove_ephemeral_key(&mut self, public_key_hex: &str) -> Result<(), StorageError> {
        self.db.connection().execute(
            "DELETE FROM ephemeral_keys WHERE public_key_hex = ?1",
            params![public_key_hex],
        )?;
        Ok(())
    }
}

impl ConversationStore for ChatStorage {
    /// Saves conversation metadata.
    fn save_conversation(&mut self, meta: &ConversationMeta) -> Result<(), StorageError> {
        self.db.connection().execute(
            "INSERT OR REPLACE INTO conversations (local_convo_id, remote_convo_id, convo_type) VALUES (?1, ?2, ?3)",
            params![meta.local_convo_id, meta.remote_convo_id, meta.kind.as_str()],
        )?;
        Ok(())
    }

    /// Loads a single conversation record by its local ID.
    fn load_conversation(
        &self,
        local_convo_id: &str,
    ) -> Result<Option<ConversationMeta>, StorageError> {
        let mut stmt = self.db.connection().prepare(
            "SELECT local_convo_id, remote_convo_id, convo_type FROM conversations WHERE local_convo_id = ?1",
        )?;

        let result = stmt.query_row(params![local_convo_id], |row| {
            let local_convo_id: String = row.get(0)?;
            let remote_convo_id: String = row.get(1)?;
            let convo_type: String = row.get(2)?;
            Ok(ConversationMeta {
                local_convo_id,
                remote_convo_id,
                kind: ConversationKind::from(convo_type.as_str()),
            })
        });

        match result {
            Ok(meta) => Ok(Some(meta)),
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Removes a conversation by its local ID.
    fn remove_conversation(&mut self, local_convo_id: &str) -> Result<(), StorageError> {
        self.db.connection().execute(
            "DELETE FROM conversations WHERE local_convo_id = ?1",
            params![local_convo_id],
        )?;
        Ok(())
    }

    /// Loads all conversation records.
    fn load_conversations(&self) -> Result<Vec<ConversationMeta>, StorageError> {
        let mut stmt = self
            .db
            .connection()
            .prepare("SELECT local_convo_id, remote_convo_id, convo_type FROM conversations")?;

        let records = stmt
            .query_map([], |row| {
                let local_convo_id: String = row.get(0)?;
                let remote_convo_id: String = row.get(1)?;
                let convo_type: String = row.get(2)?;
                Ok(ConversationMeta {
                    local_convo_id,
                    remote_convo_id,
                    kind: ConversationKind::from(convo_type.as_str()),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(records)
    }

    /// Checks if a conversation exists by its local ID.
    fn has_conversation(&self, local_convo_id: &str) -> Result<bool, StorageError> {
        let exists: bool = self.db.connection().query_row(
            "SELECT EXISTS(SELECT 1 FROM conversations WHERE local_convo_id = ?1)",
            params![local_convo_id],
            |row| row.get(0),
        )?;
        Ok(exists)
    }
}

impl RatchetStore for ChatStorage {
    fn save_ratchet_state(
        &mut self,
        conversation_id: &str,
        state: &RatchetStateRecord,
        skipped_keys: &[SkippedKeyRecord],
    ) -> Result<(), StorageError> {
        let tx = self.db.transaction()?;

        // Upsert main state
        tx.execute(
            "
            INSERT INTO ratchet_state (
                conversation_id, root_key, sending_chain, receiving_chain,
                dh_self_secret, dh_remote, msg_send, msg_recv, prev_chain_len
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(conversation_id) DO UPDATE SET
                root_key = excluded.root_key,
                sending_chain = excluded.sending_chain,
                receiving_chain = excluded.receiving_chain,
                dh_self_secret = excluded.dh_self_secret,
                dh_remote = excluded.dh_remote,
                msg_send = excluded.msg_send,
                msg_recv = excluded.msg_recv,
                prev_chain_len = excluded.prev_chain_len
            ",
            params![
                conversation_id,
                state.root_key.as_slice(),
                state.sending_chain.as_ref().map(|c| c.as_slice()),
                state.receiving_chain.as_ref().map(|c| c.as_slice()),
                state.dh_self_secret.as_slice(),
                state.dh_remote.as_ref().map(|c| c.as_slice()),
                state.msg_send,
                state.msg_recv,
                state.prev_chain_len,
            ],
        )?;

        // Sync skipped keys
        sync_skipped_keys(&tx, conversation_id, skipped_keys)?;

        tx.commit()?;
        Ok(())
    }

    fn load_ratchet_state(
        &self,
        conversation_id: &str,
    ) -> Result<RatchetStateRecord, StorageError> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "
            SELECT root_key, sending_chain, receiving_chain, dh_self_secret,
                   dh_remote, msg_send, msg_recv, prev_chain_len
            FROM ratchet_state
            WHERE conversation_id = ?1
            ",
        )?;

        stmt.query_row(params![conversation_id], |row| {
            Ok(RatchetStateRecord {
                root_key: blob_to_array(row.get::<_, Vec<u8>>(0)?),
                sending_chain: row.get::<_, Option<Vec<u8>>>(1)?.map(blob_to_array),
                receiving_chain: row.get::<_, Option<Vec<u8>>>(2)?.map(blob_to_array),
                dh_self_secret: blob_to_array(row.get::<_, Vec<u8>>(3)?),
                dh_remote: row.get::<_, Option<Vec<u8>>>(4)?.map(blob_to_array),
                msg_send: row.get(5)?,
                msg_recv: row.get(6)?,
                prev_chain_len: row.get(7)?,
            })
        })
        .map_err(|e| match e {
            RusqliteError::QueryReturnedNoRows => {
                StorageError::NotFound(conversation_id.to_string())
            }
            e => StorageError::Database(e.to_string()),
        })
    }

    fn load_skipped_keys(
        &self,
        conversation_id: &str,
    ) -> Result<Vec<SkippedKeyRecord>, StorageError> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "
            SELECT public_key, msg_num, message_key
            FROM skipped_keys
            WHERE conversation_id = ?1
            ",
        )?;

        let rows = stmt.query_map(params![conversation_id], |row| {
            Ok(SkippedKeyRecord {
                public_key: blob_to_array(row.get::<_, Vec<u8>>(0)?),
                msg_num: row.get(1)?,
                message_key: blob_to_array(row.get::<_, Vec<u8>>(2)?),
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn has_ratchet_state(&self, conversation_id: &str) -> Result<bool, StorageError> {
        let conn = self.db.connection();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM ratchet_state WHERE conversation_id = ?1",
            params![conversation_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    fn delete_ratchet_state(&mut self, conversation_id: &str) -> Result<(), StorageError> {
        let tx = self.db.transaction()?;
        tx.execute(
            "DELETE FROM skipped_keys WHERE conversation_id = ?1",
            params![conversation_id],
        )?;
        tx.execute(
            "DELETE FROM ratchet_state WHERE conversation_id = ?1",
            params![conversation_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn cleanup_old_skipped_keys(&mut self, max_age_secs: i64) -> Result<usize, StorageError> {
        let conn = self.db.connection();
        let deleted = conn.execute(
            "DELETE FROM skipped_keys WHERE created_at < strftime('%s', 'now') - ?1",
            params![max_age_secs],
        )?;
        Ok(deleted)
    }
}

/// Syncs skipped keys efficiently by computing diff and only inserting/deleting changes.
fn sync_skipped_keys(
    tx: &Transaction,
    conversation_id: &str,
    current_keys: &[SkippedKeyRecord],
) -> Result<(), StorageError> {
    // Get existing keys from DB (just the identifiers)
    let mut stmt =
        tx.prepare("SELECT public_key, msg_num FROM skipped_keys WHERE conversation_id = ?1")?;
    let existing: HashSet<([u8; 32], u32)> = stmt
        .query_map(params![conversation_id], |row| {
            Ok((
                blob_to_array(row.get::<_, Vec<u8>>(0)?),
                row.get::<_, u32>(1)?,
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();

    // Build set of current keys
    let current_set: HashSet<([u8; 32], u32)> = current_keys
        .iter()
        .map(|sk| (sk.public_key, sk.msg_num))
        .collect();

    // Delete keys that were removed (used for decryption)
    for (pk, msg_num) in existing.difference(&current_set) {
        tx.execute(
            "DELETE FROM skipped_keys WHERE conversation_id = ?1 AND public_key = ?2 AND msg_num = ?3",
            params![conversation_id, pk.as_slice(), msg_num],
        )?;
    }

    // Insert new keys
    for sk in current_keys {
        let key = (sk.public_key, sk.msg_num);
        if !existing.contains(&key) {
            tx.execute(
                "INSERT INTO skipped_keys (conversation_id, public_key, msg_num, message_key)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    conversation_id,
                    sk.public_key.as_slice(),
                    sk.msg_num,
                    sk.message_key.as_slice(),
                ],
            )?;
        }
    }

    Ok(())
}

fn blob_to_array<const N: usize>(blob: Vec<u8>) -> [u8; N] {
    blob.try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("Expected {} bytes, got {}", N, v.len()))
}

#[cfg(test)]
mod tests {
    use storage::{
        ConversationKind, ConversationMeta, ConversationStore, EphemeralKeyStore, IdentityStore,
    };

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
        let pub1: crypto::PublicKey = (&key1).into();
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
            .save_conversation(&ConversationMeta {
                local_convo_id: "local_1".into(),
                remote_convo_id: "remote_1".into(),
                kind: ConversationKind::PrivateV1,
            })
            .unwrap();
        storage
            .save_conversation(&ConversationMeta {
                local_convo_id: "local_2".into(),
                remote_convo_id: "remote_2".into(),
                kind: ConversationKind::PrivateV1,
            })
            .unwrap();

        let convos = storage.load_conversations().unwrap();
        assert_eq!(convos.len(), 2);

        // Remove one
        storage.remove_conversation("local_1").unwrap();
        let convos = storage.load_conversations().unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].local_convo_id, "local_2");
        assert_eq!(convos[0].remote_convo_id, "remote_2");
        assert_eq!(convos[0].kind.as_str(), "private_v1");
    }
}
