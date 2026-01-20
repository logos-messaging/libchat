//! Persistent storage for Double Ratchet state.
//!
//! This crate provides storage backends for persisting [`RatchetState`](double_ratchets::RatchetState)
//! across application restarts. It includes:
//!
//! - [`MemoryStorage`] - In-memory storage for testing
//! - [`SqliteStorage`] - SQLite storage with field-level encryption (requires `sqlite` feature)
//!
//! # Features
//!
//! - `sqlite` (default) - Enables SQLite storage with `rusqlite/bundled`
//! - `sqlcipher` - Enables SQLCipher full-database encryption (mutually exclusive with `sqlite`)
//!
//! # Security
//!
//! Private keys (`dh_self_secret`) are always encrypted with ChaCha20Poly1305 before storage,
//! even when using plain SQLite. For additional security, enable the `sqlcipher` feature
//! for full database encryption.
//!
//! # Example
//!
//! ```no_run
//! use double_ratchets::hkdf::DefaultDomain;
//! use double_ratchets::state::RatchetState;
//! use double_ratchets::InstallationKeyPair;
//! use double_ratchets_storage::{
//!     RatchetStorage, SqliteStorage, StorableRatchetState,
//! };
//!
//! // Create a ratchet state
//! let bob_keypair = InstallationKeyPair::generate();
//! let shared_secret = [0x42u8; 32];
//! let state: RatchetState<DefaultDomain> =
//!     RatchetState::init_sender(shared_secret, *bob_keypair.public());
//!
//! // Open storage
//! let encryption_key = [0u8; 32]; // Use proper key derivation!
//! let storage = SqliteStorage::open("ratchets.db", encryption_key).unwrap();
//!
//! // Save state
//! let session_id = [1u8; 32];
//! let storable = StorableRatchetState::from_ratchet_state(&state, "default");
//! storage.save(&session_id, &storable).unwrap();
//!
//! // Load state
//! let loaded = storage.load(&session_id).unwrap().unwrap();
//! let restored: RatchetState<DefaultDomain> = loaded.to_ratchet_state().unwrap();
//! ```

pub mod error;
pub mod memory;
#[cfg(any(feature = "sqlite", feature = "sqlcipher"))]
pub mod sqlite;
pub mod traits;
pub mod types;

// Re-exports for convenience
pub use error::StorageError;
pub use memory::MemoryStorage;
#[cfg(any(feature = "sqlite", feature = "sqlcipher"))]
pub use sqlite::{EncryptionKey, SqliteStorage};
pub use traits::{RatchetStorage, SessionId};
pub use types::{SkippedKey, StorableRatchetState};

#[cfg(test)]
mod integration_tests {
    use super::*;
    use double_ratchets::hkdf::DefaultDomain;
    use double_ratchets::state::RatchetState;
    use double_ratchets::InstallationKeyPair;

    /// Integration test: full encryption/decryption cycle with storage
    #[test]
    fn test_full_conversation_with_storage_roundtrip() {
        // Setup Alice and Bob
        let bob_keypair = InstallationKeyPair::generate();
        let shared_secret = [0x42u8; 32];

        let mut alice: RatchetState<DefaultDomain> =
            RatchetState::init_sender(shared_secret, *bob_keypair.public());
        let mut bob: RatchetState<DefaultDomain> =
            RatchetState::init_receiver(shared_secret, bob_keypair);

        let storage = MemoryStorage::new();
        let alice_session = [0xAA; 32];
        let bob_session = [0xBB; 32];

        // Alice sends a message
        let (ct1, header1) = alice.encrypt_message(b"Hello Bob!");

        // Save Alice's state
        let alice_storable = StorableRatchetState::from_ratchet_state(&alice, "default");
        storage.save(&alice_session, &alice_storable).unwrap();

        // Bob receives the message
        let pt1 = bob.decrypt_message(&ct1, header1).unwrap();
        assert_eq!(pt1, b"Hello Bob!");

        // Save Bob's state
        let bob_storable = StorableRatchetState::from_ratchet_state(&bob, "default");
        storage.save(&bob_session, &bob_storable).unwrap();

        // Simulate restart: load states from storage
        let alice_loaded = storage.load(&alice_session).unwrap().unwrap();
        let bob_loaded = storage.load(&bob_session).unwrap().unwrap();

        let mut alice_restored: RatchetState<DefaultDomain> =
            alice_loaded.to_ratchet_state().unwrap();
        let mut bob_restored: RatchetState<DefaultDomain> =
            bob_loaded.to_ratchet_state().unwrap();

        // Bob replies
        let (ct2, header2) = bob_restored.encrypt_message(b"Hi Alice!");
        let pt2 = alice_restored.decrypt_message(&ct2, header2).unwrap();
        assert_eq!(pt2, b"Hi Alice!");

        // Alice sends another message
        let (ct3, header3) = alice_restored.encrypt_message(b"How are you?");
        let pt3 = bob_restored.decrypt_message(&ct3, header3).unwrap();
        assert_eq!(pt3, b"How are you?");
    }

    /// Integration test: verify SQLite storage with encryption works
    #[cfg(any(feature = "sqlite", feature = "sqlcipher"))]
    #[test]
    fn test_sqlite_integration() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("integration_test.db");
        let key = [0x42u8; 32];

        // Setup
        let bob_keypair = InstallationKeyPair::generate();
        let shared_secret = [0x42u8; 32];
        let mut alice: RatchetState<DefaultDomain> =
            RatchetState::init_sender(shared_secret, *bob_keypair.public());
        let mut bob: RatchetState<DefaultDomain> =
            RatchetState::init_receiver(shared_secret, bob_keypair);

        let alice_session = [0xAA; 32];
        let bob_session = [0xBB; 32];

        // Exchange messages
        let (ct1, header1) = alice.encrypt_message(b"Message 1");
        bob.decrypt_message(&ct1, header1).unwrap();

        let (ct2, header2) = bob.encrypt_message(b"Response 1");
        alice.decrypt_message(&ct2, header2).unwrap();

        // Save both states
        {
            let storage = SqliteStorage::open(&db_path, key).unwrap();

            let alice_storable = StorableRatchetState::from_ratchet_state(&alice, "default");
            let bob_storable = StorableRatchetState::from_ratchet_state(&bob, "default");

            storage.save(&alice_session, &alice_storable).unwrap();
            storage.save(&bob_session, &bob_storable).unwrap();
        }

        // Reopen database (simulating restart)
        {
            let storage = SqliteStorage::open(&db_path, key).unwrap();

            let alice_loaded = storage.load(&alice_session).unwrap().unwrap();
            let bob_loaded = storage.load(&bob_session).unwrap().unwrap();

            let mut alice_restored: RatchetState<DefaultDomain> =
                alice_loaded.to_ratchet_state().unwrap();
            let mut bob_restored: RatchetState<DefaultDomain> =
                bob_loaded.to_ratchet_state().unwrap();

            // Continue conversation
            let (ct3, header3) = alice_restored.encrypt_message(b"Message 2");
            let pt3 = bob_restored.decrypt_message(&ct3, header3).unwrap();
            assert_eq!(pt3, b"Message 2");
        }
    }
}
