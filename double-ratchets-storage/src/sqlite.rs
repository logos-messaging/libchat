//! SQLite storage implementation with field-level encryption.

use std::path::Path;
use std::sync::Mutex;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::StorageError;
use crate::traits::{RatchetStore, SessionId, SkippedKeyEntry, StoredState};

/// Field encryption key type (32 bytes for ChaCha20Poly1305).
pub type EncryptionKey = [u8; 32];

/// SQLite storage with field-level encryption for secrets.
///
/// Schema:
/// - `sessions`: Core ratchet state (one row per session)
/// - `skipped_keys`: Skipped message keys (many per session)
///
/// Encrypted fields: dh_self_secret, skipped message_key
pub struct SqliteRatchetStore {
    conn: Mutex<Connection>,
    encryption_key: EncryptionKey,
}

impl SqliteRatchetStore {
    /// Open or create a SQLite database.
    pub fn open<P: AsRef<Path>>(path: P, encryption_key: EncryptionKey) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        Self::initialize(conn, encryption_key)
    }

    /// Create an in-memory database (for testing).
    pub fn open_in_memory(encryption_key: EncryptionKey) -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        Self::initialize(conn, encryption_key)
    }

    /// Open with SQLCipher full-database encryption.
    #[cfg(feature = "sqlcipher")]
    pub fn open_encrypted<P: AsRef<Path>>(
        path: P,
        db_password: &str,
        field_key: EncryptionKey,
    ) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "key", db_password)?;
        Self::initialize(conn, field_key)
    }

    fn initialize(conn: Connection, encryption_key: EncryptionKey) -> Result<Self, StorageError> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                session_id BLOB PRIMARY KEY NOT NULL,
                root_key BLOB NOT NULL,
                sending_chain BLOB,
                receiving_chain BLOB,
                dh_secret_enc BLOB NOT NULL,
                dh_secret_nonce BLOB NOT NULL,
                dh_public BLOB NOT NULL,
                dh_remote BLOB,
                msg_send INTEGER NOT NULL,
                msg_recv INTEGER NOT NULL,
                prev_chain_len INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS skipped_keys (
                session_id BLOB NOT NULL,
                dh_public BLOB NOT NULL,
                msg_num INTEGER NOT NULL,
                message_key_enc BLOB NOT NULL,
                message_key_nonce BLOB NOT NULL,
                PRIMARY KEY (session_id, dh_public, msg_num),
                FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
            );
            "#,
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
            encryption_key,
        })
    }

    fn encrypt(&self, plaintext: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12]), StorageError> {
        let cipher = ChaCha20Poly1305::new((&self.encryption_key).into());
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| StorageError::Encryption(e.to_string()))?;

        Ok((ciphertext, nonce_bytes))
    }

    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<[u8; 32], StorageError> {
        let cipher = ChaCha20Poly1305::new((&self.encryption_key).into());
        let nonce = Nonce::from_slice(nonce);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| StorageError::Decryption(e.to_string()))?;

        plaintext
            .try_into()
            .map_err(|_| StorageError::CorruptedState("wrong decrypted length".into()))
    }
}

impl RatchetStore for SqliteRatchetStore {
    fn store_root_and_chains(
        &self,
        session_id: &SessionId,
        root_key: &[u8; 32],
        sending_chain: Option<&[u8; 32]>,
        receiving_chain: Option<&[u8; 32]>,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sessions SET root_key = ?, sending_chain = ?, receiving_chain = ? WHERE session_id = ?",
            params![
                root_key.as_slice(),
                sending_chain.map(|c| c.as_slice()),
                receiving_chain.map(|c| c.as_slice()),
                session_id.as_slice(),
            ],
        )?;
        Ok(())
    }

    fn store_dh_self(
        &self,
        session_id: &SessionId,
        secret: &[u8; 32],
        public: &[u8; 32],
    ) -> Result<(), StorageError> {
        let (enc, nonce) = self.encrypt(secret)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sessions SET dh_secret_enc = ?, dh_secret_nonce = ?, dh_public = ? WHERE session_id = ?",
            params![enc.as_slice(), nonce.as_slice(), public.as_slice(), session_id.as_slice()],
        )?;
        Ok(())
    }

    fn store_dh_remote(
        &self,
        session_id: &SessionId,
        remote: Option<&[u8; 32]>,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sessions SET dh_remote = ? WHERE session_id = ?",
            params![remote.map(|r| r.as_slice()), session_id.as_slice()],
        )?;
        Ok(())
    }

    fn store_counters(
        &self,
        session_id: &SessionId,
        msg_send: u32,
        msg_recv: u32,
        prev_chain_len: u32,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sessions SET msg_send = ?, msg_recv = ?, prev_chain_len = ? WHERE session_id = ?",
            params![msg_send, msg_recv, prev_chain_len, session_id.as_slice()],
        )?;
        Ok(())
    }

    fn add_skipped_key(
        &self,
        session_id: &SessionId,
        dh_public: &[u8; 32],
        msg_num: u32,
        message_key: &[u8; 32],
    ) -> Result<(), StorageError> {
        let (enc, nonce) = self.encrypt(message_key)?;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO skipped_keys (session_id, dh_public, msg_num, message_key_enc, message_key_nonce) VALUES (?, ?, ?, ?, ?)",
            params![session_id.as_slice(), dh_public.as_slice(), msg_num, enc.as_slice(), nonce.as_slice()],
        )?;
        Ok(())
    }

    fn remove_skipped_key(
        &self,
        session_id: &SessionId,
        dh_public: &[u8; 32],
        msg_num: u32,
    ) -> Result<(), StorageError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM skipped_keys WHERE session_id = ? AND dh_public = ? AND msg_num = ?",
            params![session_id.as_slice(), dh_public.as_slice(), msg_num],
        )?;
        Ok(())
    }

    fn load_state(&self, session_id: &SessionId) -> Result<Option<StoredState>, StorageError> {
        let conn = self.conn.lock().unwrap();

        let row = conn
            .query_row(
                "SELECT root_key, sending_chain, receiving_chain, dh_secret_enc, dh_secret_nonce, dh_public, dh_remote, msg_send, msg_recv, prev_chain_len FROM sessions WHERE session_id = ?",
                [session_id.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, Option<Vec<u8>>>(6)?,
                        row.get::<_, u32>(7)?,
                        row.get::<_, u32>(8)?,
                        row.get::<_, u32>(9)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            root_key_bytes, sending_bytes, receiving_bytes,
            secret_enc, secret_nonce, dh_pub_bytes, dh_remote_bytes,
            msg_send, msg_recv, prev_chain_len,
        )) = row else {
            return Ok(None);
        };

        let nonce: [u8; 12] = secret_nonce.try_into()
            .map_err(|_| StorageError::CorruptedState("invalid nonce".into()))?;
        let dh_self_secret = self.decrypt(&secret_enc, &nonce)?;

        let root_key: [u8; 32] = root_key_bytes.try_into()
            .map_err(|_| StorageError::CorruptedState("invalid root_key".into()))?;
        let dh_self_public: [u8; 32] = dh_pub_bytes.try_into()
            .map_err(|_| StorageError::CorruptedState("invalid dh_public".into()))?;

        let sending_chain = sending_bytes
            .map(|b| b.try_into().map_err(|_| StorageError::CorruptedState("invalid sending_chain".into())))
            .transpose()?;
        let receiving_chain = receiving_bytes
            .map(|b| b.try_into().map_err(|_| StorageError::CorruptedState("invalid receiving_chain".into())))
            .transpose()?;
        let dh_remote = dh_remote_bytes
            .map(|b| b.try_into().map_err(|_| StorageError::CorruptedState("invalid dh_remote".into())))
            .transpose()?;

        // Load skipped keys
        let mut stmt = conn.prepare(
            "SELECT dh_public, msg_num, message_key_enc, message_key_nonce FROM skipped_keys WHERE session_id = ?",
        )?;
        let mut skipped_keys = Vec::new();
        let rows = stmt.query_map([session_id.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;

        for row in rows {
            let (pk_bytes, msg_num, key_enc, key_nonce) = row?;
            let dh_public: [u8; 32] = pk_bytes.try_into()
                .map_err(|_| StorageError::CorruptedState("invalid skipped dh_public".into()))?;
            let nonce: [u8; 12] = key_nonce.try_into()
                .map_err(|_| StorageError::CorruptedState("invalid skipped nonce".into()))?;
            let message_key = self.decrypt(&key_enc, &nonce)?;

            skipped_keys.push(SkippedKeyEntry { dh_public, msg_num, message_key });
        }

        Ok(Some(StoredState {
            root_key,
            sending_chain,
            receiving_chain,
            dh_self_secret,
            dh_self_public,
            dh_remote,
            msg_send,
            msg_recv,
            prev_chain_len,
            skipped_keys,
        }))
    }

    fn init_session(
        &self,
        session_id: &SessionId,
        root_key: &[u8; 32],
        sending_chain: Option<&[u8; 32]>,
        receiving_chain: Option<&[u8; 32]>,
        dh_self_secret: &[u8; 32],
        dh_self_public: &[u8; 32],
        dh_remote: Option<&[u8; 32]>,
        msg_send: u32,
        msg_recv: u32,
        prev_chain_len: u32,
    ) -> Result<(), StorageError> {
        let (secret_enc, secret_nonce) = self.encrypt(dh_self_secret)?;
        let conn = self.conn.lock().unwrap();

        conn.execute(
            r#"
            INSERT INTO sessions (session_id, root_key, sending_chain, receiving_chain, dh_secret_enc, dh_secret_nonce, dh_public, dh_remote, msg_send, msg_recv, prev_chain_len)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                root_key = excluded.root_key,
                sending_chain = excluded.sending_chain,
                receiving_chain = excluded.receiving_chain,
                dh_secret_enc = excluded.dh_secret_enc,
                dh_secret_nonce = excluded.dh_secret_nonce,
                dh_public = excluded.dh_public,
                dh_remote = excluded.dh_remote,
                msg_send = excluded.msg_send,
                msg_recv = excluded.msg_recv,
                prev_chain_len = excluded.prev_chain_len
            "#,
            params![
                session_id.as_slice(),
                root_key.as_slice(),
                sending_chain.map(|c| c.as_slice()),
                receiving_chain.map(|c| c.as_slice()),
                secret_enc.as_slice(),
                secret_nonce.as_slice(),
                dh_self_public.as_slice(),
                dh_remote.map(|r| r.as_slice()),
                msg_send,
                msg_recv,
                prev_chain_len,
            ],
        )?;
        Ok(())
    }

    fn delete_session(&self, session_id: &SessionId) -> Result<bool, StorageError> {
        let conn = self.conn.lock().unwrap();
        let changes = conn.execute(
            "DELETE FROM sessions WHERE session_id = ?",
            [session_id.as_slice()],
        )?;
        Ok(changes > 0)
    }

    fn session_exists(&self, session_id: &SessionId) -> Result<bool, StorageError> {
        let conn = self.conn.lock().unwrap();
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM sessions WHERE session_id = ?",
                [session_id.as_slice()],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        Ok(exists)
    }

    fn list_sessions(&self) -> Result<Vec<SessionId>, StorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT session_id FROM sessions")?;
        let sessions = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .filter_map(|r| r.ok())
            .filter_map(|v| v.try_into().ok())
            .collect();
        Ok(sessions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> SqliteRatchetStore {
        SqliteRatchetStore::open_in_memory([0x42u8; 32]).unwrap()
    }

    #[test]
    fn test_init_and_load() {
        let store = test_store();
        let session_id = [1u8; 32];

        store.init_session(
            &session_id,
            &[0xAA; 32], // root
            Some(&[0xBB; 32]), // sending
            None, // receiving
            &[0xCC; 32], // secret
            &[0xDD; 32], // public
            Some(&[0xEE; 32]), // remote
            5, 3, 2,
        ).unwrap();

        let state = store.load_state(&session_id).unwrap().unwrap();
        assert_eq!(state.root_key, [0xAA; 32]);
        assert_eq!(state.sending_chain, Some([0xBB; 32]));
        assert_eq!(state.receiving_chain, None);
        assert_eq!(state.dh_self_secret, [0xCC; 32]);
        assert_eq!(state.dh_self_public, [0xDD; 32]);
        assert_eq!(state.dh_remote, Some([0xEE; 32]));
        assert_eq!(state.msg_send, 5);
        assert_eq!(state.msg_recv, 3);
        assert_eq!(state.prev_chain_len, 2);
    }

    #[test]
    fn test_update_fields() {
        let store = test_store();
        let session_id = [1u8; 32];

        store.init_session(
            &session_id, &[0xAA; 32], None, None,
            &[0xCC; 32], &[0xDD; 32], None, 0, 0, 0,
        ).unwrap();

        // Update root and chains
        store.store_root_and_chains(&session_id, &[0x11; 32], Some(&[0x22; 32]), Some(&[0x33; 32])).unwrap();

        let state = store.load_state(&session_id).unwrap().unwrap();
        assert_eq!(state.root_key, [0x11; 32]);
        assert_eq!(state.sending_chain, Some([0x22; 32]));
        assert_eq!(state.receiving_chain, Some([0x33; 32]));
    }

    #[test]
    fn test_skipped_keys() {
        let store = test_store();
        let session_id = [1u8; 32];

        store.init_session(
            &session_id, &[0xAA; 32], None, None,
            &[0xCC; 32], &[0xDD; 32], None, 0, 0, 0,
        ).unwrap();

        // Add skipped keys
        store.add_skipped_key(&session_id, &[0x11; 32], 5, &[0xAB; 32]).unwrap();
        store.add_skipped_key(&session_id, &[0x11; 32], 6, &[0xCD; 32]).unwrap();

        let state = store.load_state(&session_id).unwrap().unwrap();
        assert_eq!(state.skipped_keys.len(), 2);

        // Remove one
        store.remove_skipped_key(&session_id, &[0x11; 32], 5).unwrap();

        let state = store.load_state(&session_id).unwrap().unwrap();
        assert_eq!(state.skipped_keys.len(), 1);
        assert_eq!(state.skipped_keys[0].msg_num, 6);
    }

    #[test]
    fn test_delete_cascade() {
        let store = test_store();
        let session_id = [1u8; 32];

        store.init_session(
            &session_id, &[0xAA; 32], None, None,
            &[0xCC; 32], &[0xDD; 32], None, 0, 0, 0,
        ).unwrap();
        store.add_skipped_key(&session_id, &[0x11; 32], 5, &[0xAB; 32]).unwrap();

        assert!(store.session_exists(&session_id).unwrap());

        store.delete_session(&session_id).unwrap();

        assert!(!store.session_exists(&session_id).unwrap());
        // Skipped keys should be gone too (cascade)
    }
}
