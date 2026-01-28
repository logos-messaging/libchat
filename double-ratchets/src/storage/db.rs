//! Ratchet-specific storage implementation.

use std::collections::HashSet;

use storage::{SqliteDb, StorageBackend, StorageError, params};

use super::types::RatchetStateRecord;
use crate::{
    hkdf::HkdfInfo,
    state::{RatchetState, SkippedKey},
};

/// Schema for ratchet state tables.
const RATCHET_SCHEMA: &str = "
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
";

/// Ratchet-specific storage operations.
///
/// This struct wraps a `SqliteDb` and provides domain-specific
/// storage operations for ratchet state.
pub struct RatchetStorage {
    db: SqliteDb,
}

impl RatchetStorage {
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

    /// Creates a new ratchet storage with the given database.
    fn run_migration(db: SqliteDb) -> Result<Self, StorageError> {
        // Initialize schema
        db.execute_batch(RATCHET_SCHEMA)?;
        Ok(Self { db })
    }

    /// Saves the ratchet state for a conversation.
    pub fn save<D: HkdfInfo>(
        &mut self,
        conversation_id: &str,
        state: &RatchetState<D>,
    ) -> Result<(), StorageError> {
        let tx = self.db.transaction()?;

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

        // Sync skipped keys
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
            storage::RusqliteError::QueryReturnedNoRows => {
                StorageError::NotFound(conversation_id.to_string())
            }
            e => StorageError::Database(e.to_string()),
        })
    }

    fn load_skipped_keys(&self, conversation_id: &str) -> Result<Vec<SkippedKey>, StorageError> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
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
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    /// Checks if a conversation exists.
    pub fn exists(&self, conversation_id: &str) -> Result<bool, StorageError> {
        let conn = self.db.connection();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM ratchet_state WHERE conversation_id = ?1",
            params![conversation_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Deletes a conversation and its skipped keys.
    pub fn delete(&mut self, conversation_id: &str) -> Result<(), StorageError> {
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

    /// Cleans up old skipped keys older than the given age in seconds.
    pub fn cleanup_old_skipped_keys(&mut self, max_age_secs: i64) -> Result<usize, StorageError> {
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
    tx: &storage::Transaction,
    conversation_id: &str,
    current_keys: Vec<SkippedKey>,
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
    use crate::{keypair::InstallationKeyPair, state::RatchetState, types::SharedSecret};

    fn create_test_state() -> (RatchetState, SharedSecret) {
        let shared_secret = [0x42u8; 32];
        let bob_keypair = InstallationKeyPair::generate();
        let state = RatchetState::init_sender(shared_secret, bob_keypair.public().clone());
        (state, shared_secret)
    }

    #[test]
    fn test_save_and_load() {
        let mut storage = RatchetStorage::in_memory().unwrap();
        let (state, _) = create_test_state();

        storage.save("conv1", &state).unwrap();
        let loaded: RatchetState = storage.load("conv1").unwrap();

        assert_eq!(state.root_key, loaded.root_key);
        assert_eq!(state.msg_send, loaded.msg_send);
    }

    #[test]
    fn test_exists() {
        let mut storage = RatchetStorage::in_memory().unwrap();
        let (state, _) = create_test_state();

        assert!(!storage.exists("conv1").unwrap());
        storage.save("conv1", &state).unwrap();
        assert!(storage.exists("conv1").unwrap());
    }

    #[test]
    fn test_delete() {
        let mut storage = RatchetStorage::in_memory().unwrap();
        let (state, _) = create_test_state();

        storage.save("conv1", &state).unwrap();
        assert!(storage.exists("conv1").unwrap());

        storage.delete("conv1").unwrap();
        assert!(!storage.exists("conv1").unwrap());
    }
}
