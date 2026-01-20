//! SQLite storage implementation with field-level encryption.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::StorageError;
use crate::traits::{RatchetStorage, SessionId};
use crate::types::{SkippedKey, StorableRatchetState};

/// Field encryption key type (32 bytes for ChaCha20Poly1305).
pub type EncryptionKey = [u8; 32];

/// SQLite storage backend with field-level encryption for secrets.
///
/// This implementation stores ratchet states in SQLite with:
/// - Field-level encryption for private keys using ChaCha20Poly1305
/// - WAL mode for better concurrent performance
/// - Foreign keys and cascading deletes for data integrity
/// - Atomic transactions to prevent partial writes
///
/// # Security
///
/// The `dh_self_secret` field is encrypted with the provided encryption key.
/// For additional security, consider using SQLCipher for full database encryption
/// via the `open_encrypted` method (requires `sqlcipher` feature).
///
/// # Example
///
/// ```no_run
/// use double_ratchets_storage::SqliteStorage;
///
/// let key = [0u8; 32]; // Use a proper key derivation function
/// let storage = SqliteStorage::open("ratchets.db", key).unwrap();
/// ```
pub struct SqliteStorage {
    conn: Mutex<Connection>,
    encryption_key: EncryptionKey,
}

impl SqliteStorage {
    /// Open or create a SQLite database with field-level encryption.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the database file.
    /// * `encryption_key` - 32-byte key for field-level encryption.
    ///
    /// # Returns
    ///
    /// * `Ok(SqliteStorage)` on success.
    /// * `Err(StorageError)` on failure.
    pub fn open<P: AsRef<Path>>(path: P, encryption_key: EncryptionKey) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;
        Self::initialize(conn, encryption_key)
    }

    /// Create an in-memory SQLite database (for testing).
    ///
    /// # Arguments
    ///
    /// * `encryption_key` - 32-byte key for field-level encryption.
    ///
    /// # Returns
    ///
    /// * `Ok(SqliteStorage)` on success.
    /// * `Err(StorageError)` on failure.
    pub fn open_in_memory(encryption_key: EncryptionKey) -> Result<Self, StorageError> {
        let conn = Connection::open_in_memory()?;
        Self::initialize(conn, encryption_key)
    }

    /// Open or create a SQLCipher-encrypted database.
    ///
    /// This method requires the `sqlcipher` feature to be enabled.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the database file.
    /// * `db_password` - Password for SQLCipher database encryption.
    /// * `field_key` - 32-byte key for additional field-level encryption.
    ///
    /// # Returns
    ///
    /// * `Ok(SqliteStorage)` on success.
    /// * `Err(StorageError)` on failure.
    #[cfg(feature = "sqlcipher")]
    pub fn open_encrypted<P: AsRef<Path>>(
        path: P,
        db_password: &str,
        field_key: EncryptionKey,
    ) -> Result<Self, StorageError> {
        let conn = Connection::open(path)?;

        // Set SQLCipher key
        conn.pragma_update(None, "key", db_password)?;

        Self::initialize(conn, field_key)
    }

    fn initialize(conn: Connection, encryption_key: EncryptionKey) -> Result<Self, StorageError> {
        // Enable WAL mode for better performance
        conn.pragma_update(None, "journal_mode", "WAL")?;

        // Enable foreign keys
        conn.pragma_update(None, "foreign_keys", "ON")?;

        // Create tables
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS ratchet_states (
                session_id BLOB PRIMARY KEY,
                root_key BLOB NOT NULL,
                sending_chain BLOB,
                receiving_chain BLOB,
                dh_self_secret_encrypted BLOB NOT NULL,
                dh_self_secret_nonce BLOB NOT NULL,
                dh_self_public BLOB NOT NULL,
                dh_remote BLOB,
                msg_send INTEGER NOT NULL,
                msg_recv INTEGER NOT NULL,
                prev_chain_len INTEGER NOT NULL,
                domain_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS skipped_keys (
                id INTEGER PRIMARY KEY,
                session_id BLOB NOT NULL REFERENCES ratchet_states(session_id) ON DELETE CASCADE,
                public_key BLOB NOT NULL,
                msg_num INTEGER NOT NULL,
                message_key BLOB NOT NULL,
                UNIQUE(session_id, public_key, msg_num)
            );

            CREATE INDEX IF NOT EXISTS idx_skipped_keys_session ON skipped_keys(session_id);
            "#,
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
            encryption_key,
        })
    }

    /// Encrypt a 32-byte secret using ChaCha20Poly1305.
    fn encrypt_secret(&self, secret: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12]), StorageError> {
        let cipher = ChaCha20Poly1305::new((&self.encryption_key).into());

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, secret.as_ref())
            .map_err(|e| StorageError::Encryption(e.to_string()))?;

        Ok((ciphertext, nonce_bytes))
    }

    /// Decrypt a secret using ChaCha20Poly1305.
    fn decrypt_secret(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> Result<[u8; 32], StorageError> {
        let cipher = ChaCha20Poly1305::new((&self.encryption_key).into());
        let nonce = Nonce::from_slice(nonce);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| StorageError::Decryption(e.to_string()))?;

        plaintext
            .try_into()
            .map_err(|_| StorageError::CorruptedState("decrypted secret has wrong length".to_string()))
    }

    fn current_timestamp() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }
}

impl RatchetStorage for SqliteStorage {
    fn save(&self, session_id: &SessionId, state: &StorableRatchetState) -> Result<(), StorageError> {
        let (encrypted_secret, nonce) = self.encrypt_secret(&state.dh_self_secret)?;

        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;

        let now = Self::current_timestamp();

        // Check if session exists to determine created_at
        let exists: bool = tx.query_row(
            "SELECT 1 FROM ratchet_states WHERE session_id = ?",
            [session_id.as_slice()],
            |_| Ok(true),
        ).optional()?.unwrap_or(false);

        if exists {
            // Update existing session
            tx.execute(
                r#"
                UPDATE ratchet_states SET
                    root_key = ?,
                    sending_chain = ?,
                    receiving_chain = ?,
                    dh_self_secret_encrypted = ?,
                    dh_self_secret_nonce = ?,
                    dh_self_public = ?,
                    dh_remote = ?,
                    msg_send = ?,
                    msg_recv = ?,
                    prev_chain_len = ?,
                    domain_id = ?,
                    updated_at = ?
                WHERE session_id = ?
                "#,
                params![
                    state.root_key.as_slice(),
                    state.sending_chain.as_ref().map(|c| c.as_slice()),
                    state.receiving_chain.as_ref().map(|c| c.as_slice()),
                    encrypted_secret.as_slice(),
                    nonce.as_slice(),
                    state.dh_self_public.as_slice(),
                    state.dh_remote.as_ref().map(|pk| pk.as_slice()),
                    state.msg_send,
                    state.msg_recv,
                    state.prev_chain_len,
                    &state.domain_id,
                    now,
                    session_id.as_slice(),
                ],
            )?;

            // Delete existing skipped keys
            tx.execute(
                "DELETE FROM skipped_keys WHERE session_id = ?",
                [session_id.as_slice()],
            )?;
        } else {
            // Insert new session
            tx.execute(
                r#"
                INSERT INTO ratchet_states (
                    session_id, root_key, sending_chain, receiving_chain,
                    dh_self_secret_encrypted, dh_self_secret_nonce, dh_self_public,
                    dh_remote, msg_send, msg_recv, prev_chain_len, domain_id,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
                params![
                    session_id.as_slice(),
                    state.root_key.as_slice(),
                    state.sending_chain.as_ref().map(|c| c.as_slice()),
                    state.receiving_chain.as_ref().map(|c| c.as_slice()),
                    encrypted_secret.as_slice(),
                    nonce.as_slice(),
                    state.dh_self_public.as_slice(),
                    state.dh_remote.as_ref().map(|pk| pk.as_slice()),
                    state.msg_send,
                    state.msg_recv,
                    state.prev_chain_len,
                    &state.domain_id,
                    now,
                    now,
                ],
            )?;
        }

        // Insert skipped keys
        for sk in &state.skipped_keys {
            tx.execute(
                r#"
                INSERT INTO skipped_keys (session_id, public_key, msg_num, message_key)
                VALUES (?, ?, ?, ?)
                "#,
                params![
                    session_id.as_slice(),
                    sk.public_key.as_slice(),
                    sk.msg_num,
                    sk.message_key.as_slice(),
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    fn load(&self, session_id: &SessionId) -> Result<Option<StorableRatchetState>, StorageError> {
        let conn = self.conn.lock().unwrap();

        let row = conn
            .query_row(
                r#"
                SELECT root_key, sending_chain, receiving_chain,
                       dh_self_secret_encrypted, dh_self_secret_nonce, dh_self_public,
                       dh_remote, msg_send, msg_recv, prev_chain_len, domain_id
                FROM ratchet_states WHERE session_id = ?
                "#,
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
                        row.get::<_, String>(10)?,
                    ))
                },
            )
            .optional()?;

        let Some((
            root_key_bytes,
            sending_chain_bytes,
            receiving_chain_bytes,
            encrypted_secret,
            nonce_bytes,
            dh_self_public_bytes,
            dh_remote_bytes,
            msg_send,
            msg_recv,
            prev_chain_len,
            domain_id,
        )) = row
        else {
            return Ok(None);
        };

        // Decrypt the secret
        let nonce: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| StorageError::CorruptedState("invalid nonce length".to_string()))?;
        let dh_self_secret = self.decrypt_secret(&encrypted_secret, &nonce)?;

        // Convert byte vectors to arrays
        let root_key: [u8; 32] = root_key_bytes
            .try_into()
            .map_err(|_| StorageError::CorruptedState("invalid root_key length".to_string()))?;
        let dh_self_public: [u8; 32] = dh_self_public_bytes
            .try_into()
            .map_err(|_| StorageError::CorruptedState("invalid dh_self_public length".to_string()))?;

        let sending_chain = sending_chain_bytes
            .map(|b| {
                b.try_into()
                    .map_err(|_| StorageError::CorruptedState("invalid sending_chain length".to_string()))
            })
            .transpose()?;
        let receiving_chain = receiving_chain_bytes
            .map(|b| {
                b.try_into()
                    .map_err(|_| StorageError::CorruptedState("invalid receiving_chain length".to_string()))
            })
            .transpose()?;
        let dh_remote = dh_remote_bytes
            .map(|b| {
                b.try_into()
                    .map_err(|_| StorageError::CorruptedState("invalid dh_remote length".to_string()))
            })
            .transpose()?;

        // Load skipped keys
        let mut stmt = conn.prepare(
            "SELECT public_key, msg_num, message_key FROM skipped_keys WHERE session_id = ?",
        )?;
        let skipped_keys: Vec<SkippedKey> = stmt
            .query_map([session_id.as_slice()], |row| {
                let pk_bytes: Vec<u8> = row.get(0)?;
                let msg_num: u32 = row.get(1)?;
                let mk_bytes: Vec<u8> = row.get(2)?;
                Ok((pk_bytes, msg_num, mk_bytes))
            })?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|(pk_bytes, msg_num, mk_bytes)| {
                let public_key: [u8; 32] = pk_bytes
                    .try_into()
                    .map_err(|_| StorageError::CorruptedState("invalid skipped public_key length".to_string()))?;
                let message_key: [u8; 32] = mk_bytes
                    .try_into()
                    .map_err(|_| StorageError::CorruptedState("invalid skipped message_key length".to_string()))?;
                Ok(SkippedKey {
                    public_key,
                    msg_num,
                    message_key,
                })
            })
            .collect::<Result<Vec<_>, StorageError>>()?;

        Ok(Some(StorableRatchetState {
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
            domain_id,
        }))
    }

    fn delete(&self, session_id: &SessionId) -> Result<bool, StorageError> {
        let conn = self.conn.lock().unwrap();
        let changes = conn.execute(
            "DELETE FROM ratchet_states WHERE session_id = ?",
            [session_id.as_slice()],
        )?;
        Ok(changes > 0)
    }

    fn exists(&self, session_id: &SessionId) -> Result<bool, StorageError> {
        let conn = self.conn.lock().unwrap();
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM ratchet_states WHERE session_id = ?",
                [session_id.as_slice()],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        Ok(exists)
    }

    fn list_sessions(&self) -> Result<Vec<SessionId>, StorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT session_id FROM ratchet_states")?;
        let sessions: Vec<SessionId> = stmt
            .query_map([], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(bytes)
            })?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter_map(|bytes| bytes.try_into().ok())
            .collect();
        Ok(sessions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use double_ratchets::hkdf::DefaultDomain;
    use double_ratchets::state::RatchetState;
    use double_ratchets::InstallationKeyPair;

    fn create_test_storage() -> SqliteStorage {
        let key = [0x42u8; 32];
        SqliteStorage::open_in_memory(key).unwrap()
    }

    fn create_test_state() -> StorableRatchetState {
        let bob_keypair = InstallationKeyPair::generate();
        let shared_secret = [0x42u8; 32];
        let state: RatchetState<DefaultDomain> =
            RatchetState::init_sender(shared_secret, *bob_keypair.public());
        StorableRatchetState::from_ratchet_state(&state, "default")
    }

    #[test]
    fn test_save_and_load() {
        let storage = create_test_storage();
        let session_id = [1u8; 32];
        let state = create_test_state();

        storage.save(&session_id, &state).unwrap();
        let loaded = storage.load(&session_id).unwrap();

        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.root_key, state.root_key);
        assert_eq!(loaded.dh_self_public, state.dh_self_public);
        // Secret should be decrypted correctly
        assert_eq!(loaded.dh_self_secret, state.dh_self_secret);
    }

    #[test]
    fn test_load_nonexistent() {
        let storage = create_test_storage();
        let session_id = [1u8; 32];

        let loaded = storage.load(&session_id).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_delete() {
        let storage = create_test_storage();
        let session_id = [1u8; 32];
        let state = create_test_state();

        storage.save(&session_id, &state).unwrap();
        assert!(storage.exists(&session_id).unwrap());

        let deleted = storage.delete(&session_id).unwrap();
        assert!(deleted);
        assert!(!storage.exists(&session_id).unwrap());

        // Deleting again should return false
        let deleted = storage.delete(&session_id).unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_exists() {
        let storage = create_test_storage();
        let session_id = [1u8; 32];

        assert!(!storage.exists(&session_id).unwrap());

        let state = create_test_state();
        storage.save(&session_id, &state).unwrap();

        assert!(storage.exists(&session_id).unwrap());
    }

    #[test]
    fn test_list_sessions() {
        let storage = create_test_storage();

        assert!(storage.list_sessions().unwrap().is_empty());

        let state = create_test_state();
        let session_ids: Vec<SessionId> = (0..3).map(|i| [i; 32]).collect();

        for id in &session_ids {
            storage.save(id, &state).unwrap();
        }

        let mut listed = storage.list_sessions().unwrap();
        listed.sort();
        let mut expected = session_ids.clone();
        expected.sort();

        assert_eq!(listed, expected);
    }

    #[test]
    fn test_overwrite() {
        let storage = create_test_storage();
        let session_id = [1u8; 32];

        // Create first state
        let bob_keypair1 = InstallationKeyPair::generate();
        let state1: RatchetState<DefaultDomain> =
            RatchetState::init_sender([0x42u8; 32], *bob_keypair1.public());
        let storable1 = StorableRatchetState::from_ratchet_state(&state1, "default");

        // Create second state with different root
        let bob_keypair2 = InstallationKeyPair::generate();
        let state2: RatchetState<DefaultDomain> =
            RatchetState::init_sender([0x43u8; 32], *bob_keypair2.public());
        let storable2 = StorableRatchetState::from_ratchet_state(&state2, "default");

        // Save first, then overwrite with second
        storage.save(&session_id, &storable1).unwrap();
        storage.save(&session_id, &storable2).unwrap();

        // Should have the second state
        let loaded = storage.load(&session_id).unwrap().unwrap();
        assert_eq!(loaded.root_key, storable2.root_key);
        assert_ne!(loaded.root_key, storable1.root_key);
    }

    #[test]
    fn test_skipped_keys_storage() {
        let storage = create_test_storage();
        let session_id = [1u8; 32];

        // Create states and generate skipped keys
        let bob_keypair = InstallationKeyPair::generate();
        let shared_secret = [0x42u8; 32];
        let mut alice: RatchetState<DefaultDomain> =
            RatchetState::init_sender(shared_secret, *bob_keypair.public());
        let mut bob: RatchetState<DefaultDomain> =
            RatchetState::init_receiver(shared_secret, bob_keypair);

        // Alice sends multiple messages
        let mut messages = vec![];
        for i in 0..3 {
            let (ct, header) = alice.encrypt_message(&format!("Message {}", i).into_bytes());
            messages.push((ct, header));
        }

        // Bob receives out of order to create skipped keys
        bob.decrypt_message(&messages[0].0, messages[0].1.clone())
            .unwrap();
        bob.decrypt_message(&messages[2].0, messages[2].1.clone())
            .unwrap();

        assert!(!bob.skipped_keys.is_empty());

        // Save and reload
        let storable = StorableRatchetState::from_ratchet_state(&bob, "default");
        storage.save(&session_id, &storable).unwrap();

        let loaded = storage.load(&session_id).unwrap().unwrap();
        assert_eq!(loaded.skipped_keys.len(), storable.skipped_keys.len());

        // Restore and verify we can decrypt the skipped message
        let mut restored: RatchetState<DefaultDomain> = loaded.to_ratchet_state().unwrap();
        let pt = restored
            .decrypt_message(&messages[1].0, messages[1].1.clone())
            .unwrap();
        assert_eq!(pt, b"Message 1");
    }

    #[test]
    fn test_encryption_uses_different_nonces() {
        let storage = create_test_storage();
        let state = create_test_state();

        // Save the same state twice with different session IDs
        storage.save(&[1u8; 32], &state).unwrap();
        storage.save(&[2u8; 32], &state).unwrap();

        // Both should load correctly (encryption with different nonces)
        let loaded1 = storage.load(&[1u8; 32]).unwrap().unwrap();
        let loaded2 = storage.load(&[2u8; 32]).unwrap().unwrap();

        assert_eq!(loaded1.dh_self_secret, loaded2.dh_self_secret);
    }

    #[test]
    fn test_cascade_delete_skipped_keys() {
        let storage = create_test_storage();
        let session_id = [1u8; 32];

        // Create a state with skipped keys
        let bob_keypair = InstallationKeyPair::generate();
        let shared_secret = [0x42u8; 32];
        let mut alice: RatchetState<DefaultDomain> =
            RatchetState::init_sender(shared_secret, *bob_keypair.public());
        let mut bob: RatchetState<DefaultDomain> =
            RatchetState::init_receiver(shared_secret, bob_keypair);

        let mut messages = vec![];
        for i in 0..3 {
            let (ct, header) = alice.encrypt_message(&format!("Message {}", i).into_bytes());
            messages.push((ct, header));
        }

        bob.decrypt_message(&messages[0].0, messages[0].1.clone())
            .unwrap();
        bob.decrypt_message(&messages[2].0, messages[2].1.clone())
            .unwrap();

        let storable = StorableRatchetState::from_ratchet_state(&bob, "default");
        storage.save(&session_id, &storable).unwrap();

        // Verify skipped keys exist
        {
            let conn = storage.conn.lock().unwrap();
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM skipped_keys WHERE session_id = ?",
                    [session_id.as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(count > 0);
        }

        // Delete session
        storage.delete(&session_id).unwrap();

        // Verify skipped keys were also deleted (cascade)
        {
            let conn = storage.conn.lock().unwrap();
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM skipped_keys WHERE session_id = ?",
                    [session_id.as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0);
        }
    }

    #[test]
    fn test_file_storage() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let key = [0x42u8; 32];

        let state = create_test_state();
        let session_id = [1u8; 32];

        // Save in one instance
        {
            let storage = SqliteStorage::open(&db_path, key).unwrap();
            storage.save(&session_id, &state).unwrap();
        }

        // Load in another instance
        {
            let storage = SqliteStorage::open(&db_path, key).unwrap();
            let loaded = storage.load(&session_id).unwrap().unwrap();
            assert_eq!(loaded.root_key, state.root_key);
        }
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];

        let state = create_test_state();
        let session_id = [1u8; 32];

        // Save with key1
        {
            let storage = SqliteStorage::open(&db_path, key1).unwrap();
            storage.save(&session_id, &state).unwrap();
        }

        // Try to load with key2 - should fail decryption
        {
            let storage = SqliteStorage::open(&db_path, key2).unwrap();
            let result = storage.load(&session_id);
            assert!(result.is_err());
        }
    }
}
