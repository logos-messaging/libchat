use rusqlite::{Connection, params};

use super::{RatchetStateRecord, SkippedKey, StorageError};
use crate::{hkdf::HkdfInfo, state::RatchetState};

/// Configuration for SQLite storage.
#[derive(Debug, Clone)]
pub enum StorageConfig {
    /// In-memory database (for testing).
    InMemory,
    /// File-based SQLite database (unencrypted, for local dev).
    File(String),
    /// SQLCipher encrypted database (for production).
    /// Requires the `sqlcipher` feature.
    #[cfg(feature = "sqlcipher")]
    Encrypted { path: String, key: String },
}

/// SQLite-based storage for ratchet state.
pub struct SqliteStorage {
    conn: Connection,
}

impl SqliteStorage {
    /// Creates a new SQLite storage with the given configuration.
    pub fn new(config: StorageConfig) -> Result<Self, StorageError> {
        let conn = match config {
            StorageConfig::InMemory => Connection::open_in_memory()?,
            StorageConfig::File(path) => Connection::open(path)?,
            #[cfg(feature = "sqlcipher")]
            StorageConfig::Encrypted { path, key } => {
                let conn = Connection::open(path)?;
                conn.pragma_update(None, "key", &key)?;
                conn
            }
        };

        let storage = Self { conn };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<(), StorageError> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS ratchet_state (
                conversation_id TEXT PRIMARY KEY,
                root_key BLOB NOT NULL,
                sending_chain BLOB,
                receiving_chain BLOB,
                dh_self_secret BLOB NOT NULL,
                dh_remote BLOB,
                msg_send INTEGER NOT NULL,
                msg_recv INTEGER NOT NULL,
                prev_chain_len INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS skipped_keys (
                conversation_id TEXT NOT NULL,
                public_key BLOB NOT NULL,
                msg_num INTEGER NOT NULL,
                message_key BLOB NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                PRIMARY KEY (conversation_id, public_key, msg_num),
                FOREIGN KEY (conversation_id) REFERENCES ratchet_state(conversation_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_skipped_keys_conversation
                ON skipped_keys(conversation_id);
            ",
        )?;
        Ok(())
    }

    /// Saves the ratchet state for a conversation within a transaction.
    /// Rolls back automatically if any error occurs.
    pub fn save<D: HkdfInfo>(
        &mut self,
        conversation_id: &str,
        state: &RatchetState<D>,
    ) -> Result<(), StorageError> {
        let tx = self.conn.transaction()?;

        let data = RatchetStateRecord::from(state);
        let skipped_keys: Vec<SkippedKey> = state.skipped_keys();

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
                data.root_key.as_slice(),
                data.sending_chain.as_ref().map(|c| c.as_slice()),
                data.receiving_chain.as_ref().map(|c| c.as_slice()),
                data.dh_self_secret.as_slice(),
                data.dh_remote.as_ref().map(|c| c.as_slice()),
                data.msg_send,
                data.msg_recv,
                data.prev_chain_len,
            ],
        )?;

        // Sync skipped keys efficiently - only insert new, delete removed
        sync_skipped_keys(&tx, conversation_id, skipped_keys)?;

        tx.commit()?;
        Ok(())
    }

    /// Loads the ratchet state for a conversation.
    pub fn load<D: HkdfInfo>(
        &self,
        conversation_id: &str,
    ) -> Result<RatchetState<D>, StorageError> {
        let data = self.load_state_data(conversation_id)?;
        let skipped_keys = self.load_skipped_keys(conversation_id)?;
        Ok(data.into_ratchet_state(skipped_keys))
    }

    fn load_state_data(&self, conversation_id: &str) -> Result<RatchetStateRecord, StorageError> {
        let mut stmt = self.conn.prepare(
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
            rusqlite::Error::QueryReturnedNoRows => {
                StorageError::ConversationNotFound(conversation_id.to_string())
            }
            e => StorageError::Database(e),
        })
    }

    fn load_skipped_keys(&self, conversation_id: &str) -> Result<Vec<SkippedKey>, StorageError> {
        let mut stmt = self.conn.prepare(
            "
            SELECT public_key, msg_num, message_key
            FROM skipped_keys
            WHERE conversation_id = ?1
            ",
        )?;

        let rows = stmt.query_map(params![conversation_id], |row| {
            Ok(SkippedKey {
                public_key: blob_to_array(row.get::<_, Vec<u8>>(0)?),
                msg_num: row.get(1)?,
                message_key: blob_to_array(row.get::<_, Vec<u8>>(2)?),
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::Database)
    }

    /// Checks if a conversation exists.
    pub fn exists(&self, conversation_id: &str) -> Result<bool, StorageError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM ratchet_state WHERE conversation_id = ?1",
            params![conversation_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Deletes a conversation and its skipped keys.
    pub fn delete(&mut self, conversation_id: &str) -> Result<(), StorageError> {
        let tx = self.conn.transaction()?;
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

    /// Cleans up old skipped keys older than the given age in seconds.
    pub fn cleanup_old_skipped_keys(&mut self, max_age_secs: i64) -> Result<usize, StorageError> {
        let deleted = self.conn.execute(
            "DELETE FROM skipped_keys WHERE created_at < strftime('%s', 'now') - ?1",
            params![max_age_secs],
        )?;
        Ok(deleted)
    }
}

/// Syncs skipped keys efficiently by computing diff and only inserting/deleting changes.
fn sync_skipped_keys(
    tx: &rusqlite::Transaction,
    conversation_id: &str,
    current_keys: Vec<SkippedKey>,
) -> Result<(), StorageError> {
    use std::collections::HashSet;

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
    for sk in &current_keys {
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
    use super::*;
    use crate::{hkdf::DefaultDomain, keypair::InstallationKeyPair};

    fn create_test_storage() -> SqliteStorage {
        SqliteStorage::new(StorageConfig::InMemory).unwrap()
    }

    fn create_test_state() -> (RatchetState<DefaultDomain>, RatchetState<DefaultDomain>) {
        let shared_secret = [0x42; 32];
        let bob_keypair = InstallationKeyPair::generate();
        let alice = RatchetState::init_sender(shared_secret, bob_keypair.public().clone());
        let bob = RatchetState::init_receiver(shared_secret, bob_keypair);
        (alice, bob)
    }

    #[test]
    fn test_save_and_load_sender() {
        let mut storage = create_test_storage();
        let (alice, _) = create_test_state();

        storage.save("conv1", &alice).unwrap();
        let loaded: RatchetState<DefaultDomain> = storage.load("conv1").unwrap();

        assert_eq!(alice.root_key, loaded.root_key);
        assert_eq!(alice.sending_chain, loaded.sending_chain);
        assert_eq!(alice.receiving_chain, loaded.receiving_chain);
        assert_eq!(alice.msg_send, loaded.msg_send);
        assert_eq!(alice.msg_recv, loaded.msg_recv);
        assert_eq!(alice.prev_chain_len, loaded.prev_chain_len);
        assert_eq!(
            alice.dh_self.public().to_bytes(),
            loaded.dh_self.public().to_bytes()
        );
    }

    #[test]
    fn test_save_and_load_receiver() {
        let mut storage = create_test_storage();
        let (_, bob) = create_test_state();

        storage.save("conv1", &bob).unwrap();
        let loaded: RatchetState<DefaultDomain> = storage.load("conv1").unwrap();

        assert_eq!(bob.root_key, loaded.root_key);
        assert!(loaded.dh_remote.is_none());
    }

    #[test]
    fn test_load_not_found() {
        let storage = create_test_storage();
        let result: Result<RatchetState<DefaultDomain>, _> = storage.load("nonexistent");
        assert!(matches!(result, Err(StorageError::ConversationNotFound(_))));
    }

    #[test]
    fn test_save_with_skipped_keys() {
        let mut storage = create_test_storage();
        let (mut alice, mut bob) = create_test_state();

        // Alice sends 3 messages
        let mut sent = vec![];
        for i in 0..3 {
            let plaintext = format!("Message {}", i + 1).into_bytes();
            let (ct, header) = alice.encrypt_message(&plaintext);
            sent.push((ct, header, plaintext));
        }

        // Bob receives 0 and 2, skipping 1
        bob.decrypt_message(&sent[0].0, sent[0].1.clone()).unwrap();
        bob.decrypt_message(&sent[2].0, sent[2].1.clone()).unwrap();

        assert_eq!(bob.skipped_keys.len(), 1);

        // Save and reload
        storage.save("conv1", &bob).unwrap();
        let mut loaded: RatchetState<DefaultDomain> = storage.load("conv1").unwrap();

        assert_eq!(loaded.skipped_keys.len(), 1);

        // Should be able to decrypt skipped message
        let pt = loaded
            .decrypt_message(&sent[1].0, sent[1].1.clone())
            .unwrap();
        assert_eq!(pt, sent[1].2);
    }

    #[test]
    fn test_update_existing() {
        let mut storage = create_test_storage();
        let (mut alice, mut bob) = create_test_state();

        storage.save("conv1", &alice).unwrap();

        // Exchange a message
        let (ct, header) = alice.encrypt_message(b"Hello");
        bob.decrypt_message(&ct, header).unwrap();

        // Update Alice's state
        storage.save("conv1", &alice).unwrap();

        let loaded: RatchetState<DefaultDomain> = storage.load("conv1").unwrap();
        assert_eq!(loaded.msg_send, 1);
    }

    #[test]
    fn test_exists() {
        let mut storage = create_test_storage();
        let (alice, _) = create_test_state();

        assert!(!storage.exists("conv1").unwrap());
        storage.save("conv1", &alice).unwrap();
        assert!(storage.exists("conv1").unwrap());
    }

    #[test]
    fn test_delete() {
        let mut storage = create_test_storage();
        let (alice, _) = create_test_state();

        storage.save("conv1", &alice).unwrap();
        assert!(storage.exists("conv1").unwrap());

        storage.delete("conv1").unwrap();
        assert!(!storage.exists("conv1").unwrap());
    }

    #[test]
    fn test_continue_conversation_after_reload() {
        let mut storage = create_test_storage();
        let (mut alice, mut bob) = create_test_state();

        // Exchange messages
        let (ct1, h1) = alice.encrypt_message(b"Hello Bob");
        bob.decrypt_message(&ct1, h1).unwrap();

        let (ct2, h2) = bob.encrypt_message(b"Hello Alice");
        alice.decrypt_message(&ct2, h2).unwrap();

        // Save both
        storage.save("alice", &alice).unwrap();
        storage.save("bob", &bob).unwrap();

        // Reload
        let mut alice_new: RatchetState<DefaultDomain> = storage.load("alice").unwrap();
        let mut bob_new: RatchetState<DefaultDomain> = storage.load("bob").unwrap();

        // Continue conversation
        let (ct3, h3) = alice_new.encrypt_message(b"After reload");
        let pt3 = bob_new.decrypt_message(&ct3, h3).unwrap();
        assert_eq!(pt3, b"After reload");

        let (ct4, h4) = bob_new.encrypt_message(b"Reply after reload");
        let pt4 = alice_new.decrypt_message(&ct4, h4).unwrap();
        assert_eq!(pt4, b"Reply after reload");
    }
}
