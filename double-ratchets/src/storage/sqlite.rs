//! SQLite/SQLCipher implementation of RatchetStore.

use storage::{params, RusqliteError, SqliteDb};

use super::store::{RatchetStateData, RatchetStore, SkippedKeyId, SkippedMessageKey, StoreError};
use crate::keypair::InstallationKeyPair;
use crate::types::MessageKey;

/// Schema for ratchet state tables.
const RATCHET_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS ratchet_state (
        conversation_id TEXT PRIMARY KEY,
        root_key BLOB NOT NULL,
        sending_chain BLOB,
        receiving_chain BLOB,
        dh_self_secret BLOB NOT NULL,
        dh_self_public BLOB NOT NULL,
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

/// SQLite/SQLCipher backed ratchet store.
pub struct SqliteRatchetStore {
    db: SqliteDb,
}

impl SqliteRatchetStore {
    /// Creates a new encrypted SQLite store.
    pub fn new(path: &str, key: &str) -> Result<Self, StoreError> {
        let db = SqliteDb::sqlcipher(path.to_string(), key.to_string())
            .map_err(|e| StoreError::Storage(e.to_string()))?;
        Self::init(db)
    }

    /// Creates an in-memory store (useful for testing).
    pub fn in_memory() -> Result<Self, StoreError> {
        let db = SqliteDb::in_memory().map_err(|e| StoreError::Storage(e.to_string()))?;
        Self::init(db)
    }

    fn init(db: SqliteDb) -> Result<Self, StoreError> {
        db.connection()
            .execute_batch(RATCHET_SCHEMA)
            .map_err(|e| StoreError::Storage(e.to_string()))?;
        Ok(Self { db })
    }
}

impl RatchetStore for SqliteRatchetStore {
    fn save_state(
        &mut self,
        conversation_id: &str,
        state: &RatchetStateData,
    ) -> Result<(), StoreError> {
        let conn = self.db.connection();
        conn.execute(
            "
            INSERT INTO ratchet_state (
                conversation_id, root_key, sending_chain, receiving_chain,
                dh_self_secret, dh_self_public, dh_remote, msg_send, msg_recv, prev_chain_len
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(conversation_id) DO UPDATE SET
                root_key = excluded.root_key,
                sending_chain = excluded.sending_chain,
                receiving_chain = excluded.receiving_chain,
                dh_self_secret = excluded.dh_self_secret,
                dh_self_public = excluded.dh_self_public,
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
                state.dh_self.secret_bytes().as_slice(),
                state.dh_self.public().as_bytes().as_slice(),
                state.dh_remote.as_ref().map(|c| c.as_slice()),
                state.msg_send,
                state.msg_recv,
                state.prev_chain_len,
            ],
        )
        .map_err(|e| StoreError::Storage(e.to_string()))?;
        Ok(())
    }

    fn load_state(&self, conversation_id: &str) -> Result<RatchetStateData, StoreError> {
        let conn = self.db.connection();
        let mut stmt = conn
            .prepare(
                "
            SELECT root_key, sending_chain, receiving_chain, dh_self_secret, dh_self_public,
                   dh_remote, msg_send, msg_recv, prev_chain_len
            FROM ratchet_state
            WHERE conversation_id = ?1
            ",
            )
            .map_err(|e| StoreError::Storage(e.to_string()))?;

        stmt.query_row(params![conversation_id], |row| {
            let secret_bytes: Vec<u8> = row.get(3)?;
            let public_bytes: Vec<u8> = row.get(4)?;

            Ok(RatchetStateData {
                root_key: blob_to_array(row.get::<_, Vec<u8>>(0)?),
                sending_chain: row.get::<_, Option<Vec<u8>>>(1)?.map(blob_to_array),
                receiving_chain: row.get::<_, Option<Vec<u8>>>(2)?.map(blob_to_array),
                dh_self: InstallationKeyPair::from_bytes(
                    blob_to_array(secret_bytes),
                    blob_to_array(public_bytes),
                ),
                dh_remote: row.get::<_, Option<Vec<u8>>>(5)?.map(blob_to_array),
                msg_send: row.get(6)?,
                msg_recv: row.get(7)?,
                prev_chain_len: row.get(8)?,
            })
        })
        .map_err(|e| match e {
            RusqliteError::QueryReturnedNoRows => {
                StoreError::NotFound(conversation_id.to_string())
            }
            e => StoreError::Storage(e.to_string()),
        })
    }

    fn exists(&self, conversation_id: &str) -> Result<bool, StoreError> {
        let conn = self.db.connection();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM ratchet_state WHERE conversation_id = ?1",
                params![conversation_id],
                |row| row.get(0),
            )
            .map_err(|e| StoreError::Storage(e.to_string()))?;
        Ok(count > 0)
    }

    fn delete(&mut self, conversation_id: &str) -> Result<(), StoreError> {
        let conn = self.db.connection();
        // Skipped keys are deleted via CASCADE
        conn.execute(
            "DELETE FROM ratchet_state WHERE conversation_id = ?1",
            params![conversation_id],
        )
        .map_err(|e| StoreError::Storage(e.to_string()))?;
        Ok(())
    }

    fn get_skipped_key(
        &self,
        conversation_id: &str,
        id: &SkippedKeyId,
    ) -> Result<Option<MessageKey>, StoreError> {
        let conn = self.db.connection();
        let result: Result<Vec<u8>, _> = conn.query_row(
            "SELECT message_key FROM skipped_keys 
             WHERE conversation_id = ?1 AND public_key = ?2 AND msg_num = ?3",
            params![conversation_id, id.public_key.as_slice(), id.msg_num],
            |row| row.get(0),
        );

        match result {
            Ok(bytes) => Ok(Some(blob_to_array(bytes))),
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StoreError::Storage(e.to_string())),
        }
    }

    fn add_skipped_key(
        &mut self,
        conversation_id: &str,
        key: SkippedMessageKey,
    ) -> Result<(), StoreError> {
        let conn = self.db.connection();
        conn.execute(
            "INSERT OR REPLACE INTO skipped_keys (conversation_id, public_key, msg_num, message_key)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                conversation_id,
                key.id.public_key.as_slice(),
                key.id.msg_num,
                key.message_key.as_slice(),
            ],
        )
        .map_err(|e| StoreError::Storage(e.to_string()))?;
        Ok(())
    }

    fn remove_skipped_key(
        &mut self,
        conversation_id: &str,
        id: &SkippedKeyId,
    ) -> Result<(), StoreError> {
        let conn = self.db.connection();
        conn.execute(
            "DELETE FROM skipped_keys WHERE conversation_id = ?1 AND public_key = ?2 AND msg_num = ?3",
            params![conversation_id, id.public_key.as_slice(), id.msg_num],
        )
        .map_err(|e| StoreError::Storage(e.to_string()))?;
        Ok(())
    }

    fn get_all_skipped_keys(
        &self,
        conversation_id: &str,
    ) -> Result<Vec<SkippedMessageKey>, StoreError> {
        let conn = self.db.connection();
        let mut stmt = conn
            .prepare(
                "SELECT public_key, msg_num, message_key FROM skipped_keys WHERE conversation_id = ?1",
            )
            .map_err(|e| StoreError::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(params![conversation_id], |row| {
                Ok(SkippedMessageKey {
                    id: SkippedKeyId {
                        public_key: blob_to_array(row.get::<_, Vec<u8>>(0)?),
                        msg_num: row.get(1)?,
                    },
                    message_key: blob_to_array(row.get::<_, Vec<u8>>(2)?),
                })
            })
            .map_err(|e| StoreError::Storage(e.to_string()))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::Storage(e.to_string()))
    }

    fn clear_skipped_keys(&mut self, conversation_id: &str) -> Result<(), StoreError> {
        let conn = self.db.connection();
        conn.execute(
            "DELETE FROM skipped_keys WHERE conversation_id = ?1",
            params![conversation_id],
        )
        .map_err(|e| StoreError::Storage(e.to_string()))?;
        Ok(())
    }
}

fn blob_to_array<const N: usize>(blob: Vec<u8>) -> [u8; N] {
    blob.try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("Expected {} bytes, got {}", N, v.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_state() -> RatchetStateData {
        RatchetStateData {
            root_key: [0x42; 32],
            sending_chain: Some([0x01; 32]),
            receiving_chain: None,
            dh_self: InstallationKeyPair::generate(),
            dh_remote: Some([0x02; 32]),
            msg_send: 0,
            msg_recv: 0,
            prev_chain_len: 0,
        }
    }

    #[test]
    fn test_save_and_load() {
        let mut store = SqliteRatchetStore::in_memory().unwrap();
        let state = create_test_state();

        store.save_state("conv1", &state).unwrap();
        let loaded = store.load_state("conv1").unwrap();

        assert_eq!(state.root_key, loaded.root_key);
        assert_eq!(state.msg_send, loaded.msg_send);
    }

    #[test]
    fn test_exists() {
        let mut store = SqliteRatchetStore::in_memory().unwrap();
        let state = create_test_state();

        assert!(!store.exists("conv1").unwrap());
        store.save_state("conv1", &state).unwrap();
        assert!(store.exists("conv1").unwrap());
    }

    #[test]
    fn test_skipped_keys() {
        let mut store = SqliteRatchetStore::in_memory().unwrap();
        let state = create_test_state();
        store.save_state("conv1", &state).unwrap();

        let id = SkippedKeyId {
            public_key: [0x01; 32],
            msg_num: 5,
        };
        let key = SkippedMessageKey {
            id: id.clone(),
            message_key: [0xAB; 32],
        };

        // Add key
        store.add_skipped_key("conv1", key.clone()).unwrap();
        assert_eq!(
            store.get_skipped_key("conv1", &id).unwrap(),
            Some([0xAB; 32])
        );

        // Get all
        let all = store.get_all_skipped_keys("conv1").unwrap();
        assert_eq!(all.len(), 1);

        // Remove key
        store.remove_skipped_key("conv1", &id).unwrap();
        assert_eq!(store.get_skipped_key("conv1", &id).unwrap(), None);
    }

    #[test]
    fn test_delete_cascades() {
        let mut store = SqliteRatchetStore::in_memory().unwrap();
        let state = create_test_state();
        store.save_state("conv1", &state).unwrap();

        let id = SkippedKeyId {
            public_key: [0x01; 32],
            msg_num: 5,
        };
        let key = SkippedMessageKey {
            id: id.clone(),
            message_key: [0xAB; 32],
        };
        store.add_skipped_key("conv1", key).unwrap();

        // Delete conversation - skipped keys should be deleted too
        store.delete("conv1").unwrap();
        assert!(!store.exists("conv1").unwrap());
    }
}
