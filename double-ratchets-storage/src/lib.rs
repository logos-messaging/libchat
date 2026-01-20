//! Persistent storage for Double Ratchet state.
//!
//! This crate provides storage backends for persisting [`RatchetState`](double_ratchets::RatchetState)
//! with automatic field-level persistence on each ratchet operation.
//!
//! # Main API
//!
//! - [`PersistentRatchet`] - Wrapper that auto-persists state changes during encrypt/decrypt
//! - [`SqliteRatchetStore`] - SQLite backend with field-level encryption
//! - [`RatchetStore`] - Trait for implementing custom storage backends
//!
//! # Features
//!
//! - `sqlite` (default) - Enables SQLite storage with `rusqlite/bundled`
//! - `sqlcipher` - Enables SQLCipher full-database encryption (mutually exclusive with `sqlite`)
//!
//! # Security
//!
//! Private keys (`dh_self_secret`) and message keys are always encrypted with ChaCha20Poly1305
//! before storage, even when using plain SQLite. For additional security, enable the `sqlcipher`
//! feature for full database encryption.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use double_ratchets::hkdf::DefaultDomain;
//! use double_ratchets::InstallationKeyPair;
//! use double_ratchets_storage::{PersistentRatchet, RatchetStore, SqliteRatchetStore};
//!
//! // Open storage
//! let encryption_key = [0u8; 32]; // Use proper key derivation!
//! let store: Arc<dyn RatchetStore> =
//!     Arc::new(SqliteRatchetStore::open("ratchets.db", encryption_key).unwrap());
//!
//! // Initialize sender
//! let bob_keypair = InstallationKeyPair::generate();
//! let shared_secret = [0x42u8; 32];
//! let session_id = [1u8; 32];
//!
//! let mut alice: PersistentRatchet<DefaultDomain> = PersistentRatchet::init_sender(
//!     Arc::clone(&store),
//!     session_id,
//!     shared_secret,
//!     *bob_keypair.public(),
//! ).unwrap();
//!
//! // Encrypt - state is automatically persisted
//! let (ciphertext, header) = alice.encrypt_message(b"Hello!").unwrap();
//!
//! // Later: load from storage
//! let alice_restored: PersistentRatchet<DefaultDomain> =
//!     PersistentRatchet::load(store, session_id).unwrap().unwrap();
//! ```

pub mod error;
#[cfg(any(feature = "sqlite", feature = "sqlcipher"))]
pub mod persistent;
#[cfg(any(feature = "sqlite", feature = "sqlcipher"))]
pub mod sqlite;
pub mod traits;

// Re-exports for convenience
pub use error::StorageError;
#[cfg(any(feature = "sqlite", feature = "sqlcipher"))]
pub use persistent::{PersistentRatchet, PersistentRatchetError};
#[cfg(any(feature = "sqlite", feature = "sqlcipher"))]
pub use sqlite::{EncryptionKey, SqliteRatchetStore};
pub use traits::{RatchetStore, SessionId, SkippedKeyEntry, StoredState};

#[cfg(all(test, any(feature = "sqlite", feature = "sqlcipher")))]
mod integration_tests {
    use super::*;
    use double_ratchets::hkdf::DefaultDomain;
    use double_ratchets::InstallationKeyPair;
    use std::sync::Arc;

    /// Integration test: full conversation with auto-persist
    #[test]
    fn test_full_conversation_with_auto_persist() {
        let store: Arc<dyn RatchetStore> =
            Arc::new(SqliteRatchetStore::open_in_memory([0x42u8; 32]).unwrap());
        let alice_session = [0xAA; 32];
        let bob_session = [0xBB; 32];

        let bob_keypair = InstallationKeyPair::generate();
        let shared_secret = [0x42u8; 32];

        // Initialize both parties - state is auto-persisted
        let mut alice: PersistentRatchet<DefaultDomain> = PersistentRatchet::init_sender(
            Arc::clone(&store),
            alice_session,
            shared_secret,
            *bob_keypair.public(),
        )
        .unwrap();

        let mut bob: PersistentRatchet<DefaultDomain> = PersistentRatchet::init_receiver(
            Arc::clone(&store),
            bob_session,
            shared_secret,
            bob_keypair,
        )
        .unwrap();

        // Alice sends - state auto-persisted
        let (ct1, header1) = alice.encrypt_message(b"Hello Bob!").unwrap();
        let pt1 = bob.decrypt_message(&ct1, header1).unwrap();
        assert_eq!(pt1, b"Hello Bob!");

        // Verify state was persisted
        assert!(store.session_exists(&alice_session).unwrap());
        assert!(store.session_exists(&bob_session).unwrap());

        // Bob replies - state auto-persisted
        let (ct2, header2) = bob.encrypt_message(b"Hi Alice!").unwrap();
        let pt2 = alice.decrypt_message(&ct2, header2).unwrap();
        assert_eq!(pt2, b"Hi Alice!");

        // Alice sends another - state auto-persisted
        let (ct3, header3) = alice.encrypt_message(b"How are you?").unwrap();
        let pt3 = bob.decrypt_message(&ct3, header3).unwrap();
        assert_eq!(pt3, b"How are you?");
    }

    /// Integration test: verify SQLite storage with file persistence
    #[test]
    fn test_sqlite_file_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("integration_test.db");
        let key = [0x42u8; 32];

        let bob_keypair = InstallationKeyPair::generate();
        let bob_pub = *bob_keypair.public();
        let shared_secret = [0x42u8; 32];
        let alice_session = [0xAA; 32];
        let bob_session = [0xBB; 32];

        // First session: exchange messages
        {
            let store: Arc<dyn RatchetStore> =
                Arc::new(SqliteRatchetStore::open(&db_path, key).unwrap());

            let mut alice: PersistentRatchet<DefaultDomain> = PersistentRatchet::init_sender(
                Arc::clone(&store),
                alice_session,
                shared_secret,
                bob_pub,
            )
            .unwrap();

            let mut bob: PersistentRatchet<DefaultDomain> = PersistentRatchet::init_receiver(
                Arc::clone(&store),
                bob_session,
                shared_secret,
                bob_keypair,
            )
            .unwrap();

            let (ct1, h1) = alice.encrypt_message(b"Message 1").unwrap();
            bob.decrypt_message(&ct1, h1).unwrap();

            let (ct2, h2) = bob.encrypt_message(b"Response 1").unwrap();
            alice.decrypt_message(&ct2, h2).unwrap();
        }

        // Reopen database (simulating restart)
        {
            let store: Arc<dyn RatchetStore> =
                Arc::new(SqliteRatchetStore::open(&db_path, key).unwrap());

            let mut alice: PersistentRatchet<DefaultDomain> =
                PersistentRatchet::load(Arc::clone(&store), alice_session)
                    .unwrap()
                    .unwrap();

            let mut bob: PersistentRatchet<DefaultDomain> =
                PersistentRatchet::load(Arc::clone(&store), bob_session)
                    .unwrap()
                    .unwrap();

            // Continue conversation
            let (ct3, h3) = alice.encrypt_message(b"Message 2").unwrap();
            let pt3 = bob.decrypt_message(&ct3, h3).unwrap();
            assert_eq!(pt3, b"Message 2");
        }
    }

    /// Integration test: out-of-order messages with skipped keys
    #[test]
    fn test_out_of_order_messages_persisted() {
        let store: Arc<dyn RatchetStore> =
            Arc::new(SqliteRatchetStore::open_in_memory([0x42u8; 32]).unwrap());
        let alice_session = [0xAA; 32];
        let bob_session = [0xBB; 32];

        let bob_keypair = InstallationKeyPair::generate();
        let shared_secret = [0x42u8; 32];

        let mut alice: PersistentRatchet<DefaultDomain> = PersistentRatchet::init_sender(
            Arc::clone(&store),
            alice_session,
            shared_secret,
            *bob_keypair.public(),
        )
        .unwrap();

        let mut bob: PersistentRatchet<DefaultDomain> = PersistentRatchet::init_receiver(
            Arc::clone(&store),
            bob_session,
            shared_secret,
            bob_keypair,
        )
        .unwrap();

        // Alice sends 4 messages
        let mut messages = vec![];
        for i in 0..4 {
            let (ct, h) = alice
                .encrypt_message(format!("Message {}", i).as_bytes())
                .unwrap();
            messages.push((ct, h));
        }

        // Bob receives 0, 2, 3 (skipping 1)
        bob.decrypt_message(&messages[0].0, messages[0].1.clone())
            .unwrap();
        bob.decrypt_message(&messages[2].0, messages[2].1.clone())
            .unwrap();
        bob.decrypt_message(&messages[3].0, messages[3].1.clone())
            .unwrap();

        // Verify skipped key is persisted
        let bob_state = store.load_state(&bob_session).unwrap().unwrap();
        assert_eq!(bob_state.skipped_keys.len(), 1);
        assert_eq!(bob_state.skipped_keys[0].msg_num, 1);

        // Now receive the skipped message
        let pt1 = bob
            .decrypt_message(&messages[1].0, messages[1].1.clone())
            .unwrap();
        assert_eq!(pt1, b"Message 1");

        // Skipped key should be removed from storage
        let bob_state = store.load_state(&bob_session).unwrap().unwrap();
        assert!(bob_state.skipped_keys.is_empty());
    }
}
