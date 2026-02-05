//! Chat-specific storage implementation.

use std::collections::HashMap;

use storage::{RusqliteError, SqliteDb, StorageConfig, StorageError, params};
use x25519_dalek::StaticSecret;

use super::types::{ChatRecord, IdentityRecord, RatchetStateRecord, SkippedKeyRecord};
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

    -- Ratchet state for each conversation
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

    -- Skipped message keys (for out-of-order messages)
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

/// Chat-specific storage operations.
///
/// This struct wraps a `SqliteDb` and provides domain-specific
/// storage operations for chat state.
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

    // ==================== Chat Operations ====================

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

    /// Checks if a chat exists in storage.
    pub fn chat_exists(&self, chat_id: &str) -> Result<bool, StorageError> {
        let mut stmt = self
            .db
            .connection()
            .prepare("SELECT 1 FROM chats WHERE chat_id = ?1")?;

        let exists = stmt.exists(params![chat_id])?;
        Ok(exists)
    }

    /// Deletes a chat record and its ratchet state.
    pub fn delete_chat(&mut self, chat_id: &str) -> Result<(), StorageError> {
        let tx = self.db.transaction()?;
        // Delete skipped keys first (foreign key constraint)
        tx.execute(
            "DELETE FROM skipped_keys WHERE conversation_id = ?1",
            params![chat_id],
        )?;
        tx.execute(
            "DELETE FROM ratchet_state WHERE conversation_id = ?1",
            params![chat_id],
        )?;
        tx.execute("DELETE FROM chats WHERE chat_id = ?1", params![chat_id])?;
        tx.commit()?;
        Ok(())
    }

    // ==================== Ratchet State Operations ====================

    /// Saves the ratchet state for a conversation.
    pub fn save_ratchet_state(
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

        // Sync skipped keys: delete old ones and insert new
        tx.execute(
            "DELETE FROM skipped_keys WHERE conversation_id = ?1",
            params![conversation_id],
        )?;

        for sk in skipped_keys {
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

        tx.commit()?;
        Ok(())
    }

    /// Loads the ratchet state for a conversation.
    pub fn load_ratchet_state(
        &self,
        conversation_id: &str,
    ) -> Result<Option<(RatchetStateRecord, Vec<SkippedKeyRecord>)>, StorageError> {
        // Load main state
        let state = self.load_ratchet_state_data(conversation_id)?;
        let state = match state {
            Some(s) => s,
            None => return Ok(None),
        };

        // Load skipped keys
        let skipped_keys = self.load_skipped_keys(conversation_id)?;

        Ok(Some((state, skipped_keys)))
    }

    fn load_ratchet_state_data(
        &self,
        conversation_id: &str,
    ) -> Result<Option<RatchetStateRecord>, StorageError> {
        let conn = self.db.connection();
        let mut stmt = conn.prepare(
            "
            SELECT root_key, sending_chain, receiving_chain, dh_self_secret,
                   dh_remote, msg_send, msg_recv, prev_chain_len
            FROM ratchet_state
            WHERE conversation_id = ?1
            ",
        )?;

        let result = stmt.query_row(params![conversation_id], |row| {
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
        });

        match result {
            Ok(record) => Ok(Some(record)),
            Err(RusqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StorageError::Database(e.to_string())),
        }
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

    /// Checks if a ratchet state exists for a conversation.
    pub fn ratchet_state_exists(&self, conversation_id: &str) -> Result<bool, StorageError> {
        let conn = self.db.connection();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM ratchet_state WHERE conversation_id = ?1",
            params![conversation_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }
}

/// Helper to convert a Vec<u8> to a fixed-size array.
fn blob_to_array(blob: Vec<u8>) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&blob);
    arr
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
