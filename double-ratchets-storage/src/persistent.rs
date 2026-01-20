//! Persistent ratchet wrapper that auto-saves state changes.

use std::sync::Arc;

use double_ratchets::errors::RatchetError;
use double_ratchets::hkdf::HkdfInfo;
use double_ratchets::state::{Header, RatchetState};
use double_ratchets::InstallationKeyPair;
use x25519_dalek::PublicKey;

use crate::error::StorageError;
use crate::traits::{RatchetStore, SessionId};

/// A wrapper around `RatchetState` that automatically persists state changes.
///
/// This wrapper intercepts `encrypt_message` and `decrypt_message` calls,
/// delegates to the underlying `RatchetState`, and then persists the changed
/// fields to storage.
///
/// # Example
///
/// ```no_run
/// use double_ratchets::hkdf::DefaultDomain;
/// use double_ratchets::InstallationKeyPair;
/// use double_ratchets_storage::{PersistentRatchet, SqliteRatchetStore};
/// use std::sync::Arc;
///
/// let store = Arc::new(SqliteRatchetStore::open_in_memory([0u8; 32]).unwrap());
/// let session_id = [1u8; 32];
/// let bob_pub = InstallationKeyPair::generate().public().clone();
/// let shared_secret = [0x42u8; 32];
///
/// let mut ratchet: PersistentRatchet<DefaultDomain> =
///     PersistentRatchet::init_sender(store, session_id, shared_secret, bob_pub).unwrap();
///
/// let (ciphertext, header) = ratchet.encrypt_message(b"Hello!").unwrap();
/// ```
pub struct PersistentRatchet<D: HkdfInfo> {
    state: RatchetState<D>,
    store: Arc<dyn RatchetStore>,
    session_id: SessionId,
}

impl<D: HkdfInfo> PersistentRatchet<D> {
    /// Initialize as the sender (first to send a message).
    ///
    /// Creates a new ratchet state and persists it to storage.
    pub fn init_sender(
        store: Arc<dyn RatchetStore>,
        session_id: SessionId,
        shared_secret: [u8; 32],
        remote_pub: PublicKey,
    ) -> Result<Self, StorageError> {
        let state = RatchetState::<D>::init_sender(shared_secret, remote_pub);

        // Persist initial state
        store.init_session(
            &session_id,
            &state.root_key,
            state.sending_chain.as_ref(),
            state.receiving_chain.as_ref(),
            &state.dh_self.secret_bytes(),
            state.dh_self.public().as_bytes(),
            state.dh_remote.as_ref().map(|pk| pk.as_bytes()),
            state.msg_send,
            state.msg_recv,
            state.prev_chain_len,
        )?;

        Ok(Self {
            state,
            store,
            session_id,
        })
    }

    /// Initialize as the receiver (first to receive a message).
    ///
    /// Creates a new ratchet state and persists it to storage.
    pub fn init_receiver(
        store: Arc<dyn RatchetStore>,
        session_id: SessionId,
        shared_secret: [u8; 32],
        dh_self: InstallationKeyPair,
    ) -> Result<Self, StorageError> {
        let state = RatchetState::<D>::init_receiver(shared_secret, dh_self);

        // Persist initial state
        store.init_session(
            &session_id,
            &state.root_key,
            state.sending_chain.as_ref(),
            state.receiving_chain.as_ref(),
            &state.dh_self.secret_bytes(),
            state.dh_self.public().as_bytes(),
            state.dh_remote.as_ref().map(|pk| pk.as_bytes()),
            state.msg_send,
            state.msg_recv,
            state.prev_chain_len,
        )?;

        Ok(Self {
            state,
            store,
            session_id,
        })
    }

    /// Load an existing session from storage.
    pub fn load(
        store: Arc<dyn RatchetStore>,
        session_id: SessionId,
    ) -> Result<Option<Self>, StorageError> {
        let Some(stored) = store.load_state(&session_id)? else {
            return Ok(None);
        };

        // Reconstruct the keypair
        let dh_self = InstallationKeyPair::from_bytes(stored.dh_self_secret, stored.dh_self_public)
            .map_err(|e| StorageError::KeyReconstruction(e.to_string()))?;

        // Reconstruct skipped keys
        let mut skipped_keys = std::collections::HashMap::new();
        for entry in stored.skipped_keys {
            let pub_key = PublicKey::from(entry.dh_public);
            skipped_keys.insert((pub_key, entry.msg_num), entry.message_key);
        }

        let state = RatchetState::<D>::from_parts(
            stored.root_key,
            stored.sending_chain,
            stored.receiving_chain,
            dh_self,
            stored.dh_remote.map(PublicKey::from),
            stored.msg_send,
            stored.msg_recv,
            stored.prev_chain_len,
            skipped_keys,
        );

        Ok(Some(Self {
            state,
            store,
            session_id,
        }))
    }

    /// Encrypt a message and persist state changes.
    ///
    /// This may trigger a DH ratchet if the sending direction changed.
    /// All state changes are persisted to storage after encryption.
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, Header), StorageError> {
        // Check if we'll do a DH ratchet (no sending chain)
        let will_ratchet = self.state.sending_chain.is_none();

        // Perform encryption
        let (ciphertext, header) = self.state.encrypt_message(plaintext);

        // Persist changes
        if will_ratchet {
            // DH ratchet happened: root_key, sending_chain, dh_self all changed
            self.store.store_root_and_chains(
                &self.session_id,
                &self.state.root_key,
                self.state.sending_chain.as_ref(),
                self.state.receiving_chain.as_ref(),
            )?;
            self.store.store_dh_self(
                &self.session_id,
                &self.state.dh_self.secret_bytes(),
                self.state.dh_self.public().as_bytes(),
            )?;
        } else {
            // Only sending chain changed
            self.store.store_root_and_chains(
                &self.session_id,
                &self.state.root_key,
                self.state.sending_chain.as_ref(),
                self.state.receiving_chain.as_ref(),
            )?;
        }

        // Counters always change
        self.store.store_counters(
            &self.session_id,
            self.state.msg_send,
            self.state.msg_recv,
            self.state.prev_chain_len,
        )?;

        Ok((ciphertext, header))
    }

    /// Decrypt a message and persist state changes.
    ///
    /// Handles DH ratcheting, skipped messages, and replay protection.
    /// All state changes are persisted to storage after decryption.
    pub fn decrypt_message(
        &mut self,
        ciphertext_with_nonce: &[u8],
        header: Header,
    ) -> Result<Vec<u8>, PersistentRatchetError> {
        // Track skipped keys before decryption
        let skipped_before: std::collections::HashSet<_> = self
            .state
            .skipped_keys
            .keys()
            .map(|(pk, n)| (*pk.as_bytes(), *n))
            .collect();

        // Check if we'll do a DH ratchet
        let will_ratchet = self.state.dh_remote.as_ref() != Some(&header.dh_pub);

        // Perform decryption
        let plaintext = self
            .state
            .decrypt_message(ciphertext_with_nonce, header)
            .map_err(PersistentRatchetError::Ratchet)?;

        // Track skipped keys after decryption
        let skipped_after: std::collections::HashSet<_> = self
            .state
            .skipped_keys
            .keys()
            .map(|(pk, n)| (*pk.as_bytes(), *n))
            .collect();

        // Persist changes
        if will_ratchet {
            // DH ratchet happened
            self.store
                .store_root_and_chains(
                    &self.session_id,
                    &self.state.root_key,
                    self.state.sending_chain.as_ref(),
                    self.state.receiving_chain.as_ref(),
                )
                .map_err(PersistentRatchetError::Storage)?;
            self.store
                .store_dh_remote(
                    &self.session_id,
                    self.state.dh_remote.as_ref().map(|pk| pk.as_bytes()),
                )
                .map_err(PersistentRatchetError::Storage)?;
        } else {
            // Only receiving chain changed
            self.store
                .store_root_and_chains(
                    &self.session_id,
                    &self.state.root_key,
                    self.state.sending_chain.as_ref(),
                    self.state.receiving_chain.as_ref(),
                )
                .map_err(PersistentRatchetError::Storage)?;
        }

        // Counters
        self.store
            .store_counters(
                &self.session_id,
                self.state.msg_send,
                self.state.msg_recv,
                self.state.prev_chain_len,
            )
            .map_err(PersistentRatchetError::Storage)?;

        // Handle skipped keys changes
        // New skipped keys (added during skip_message_keys)
        for (pk_bytes, msg_num) in skipped_after.difference(&skipped_before) {
            let pk = PublicKey::from(*pk_bytes);
            if let Some(key) = self.state.skipped_keys.get(&(pk, *msg_num)) {
                self.store
                    .add_skipped_key(&self.session_id, pk_bytes, *msg_num, key)
                    .map_err(PersistentRatchetError::Storage)?;
            }
        }

        // Removed skipped keys (used for decryption)
        for (pk_bytes, msg_num) in skipped_before.difference(&skipped_after) {
            self.store
                .remove_skipped_key(&self.session_id, pk_bytes, *msg_num)
                .map_err(PersistentRatchetError::Storage)?;
        }

        Ok(plaintext)
    }

    /// Get a reference to the underlying state (read-only).
    pub fn state(&self) -> &RatchetState<D> {
        &self.state
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Delete this session from storage.
    pub fn delete(self) -> Result<bool, StorageError> {
        self.store.delete_session(&self.session_id)
    }
}

/// Error type for persistent ratchet operations.
#[derive(Debug)]
pub enum PersistentRatchetError {
    /// Storage operation failed.
    Storage(StorageError),
    /// Ratchet operation failed.
    Ratchet(RatchetError),
}

impl std::fmt::Display for PersistentRatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage error: {}", e),
            Self::Ratchet(e) => write!(f, "ratchet error: {:?}", e),
        }
    }
}

impl std::error::Error for PersistentRatchetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::Ratchet(_) => None,
        }
    }
}

impl From<StorageError> for PersistentRatchetError {
    fn from(e: StorageError) -> Self {
        Self::Storage(e)
    }
}

impl From<RatchetError> for PersistentRatchetError {
    fn from(e: RatchetError) -> Self {
        Self::Ratchet(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::SqliteRatchetStore;
    use double_ratchets::hkdf::DefaultDomain;

    fn test_store() -> Arc<dyn RatchetStore> {
        Arc::new(SqliteRatchetStore::open_in_memory([0x42u8; 32]).unwrap())
    }

    #[test]
    fn test_basic_roundtrip() {
        let store = test_store();
        let alice_session = [0xAA; 32];
        let bob_session = [0xBB; 32];

        let bob_keypair = InstallationKeyPair::generate();
        let shared_secret = [0x42u8; 32];

        // Initialize both parties
        let mut alice: PersistentRatchet<DefaultDomain> = PersistentRatchet::init_sender(
            Arc::clone(&store),
            alice_session,
            shared_secret,
            *bob_keypair.public(),
        )
        .unwrap();

        let mut bob: PersistentRatchet<DefaultDomain> =
            PersistentRatchet::init_receiver(Arc::clone(&store), bob_session, shared_secret, bob_keypair)
                .unwrap();

        // Alice sends a message
        let (ct, header) = alice.encrypt_message(b"Hello Bob!").unwrap();
        let pt = bob.decrypt_message(&ct, header).unwrap();
        assert_eq!(pt, b"Hello Bob!");

        // Verify state was persisted
        let alice_loaded = store.load_state(&alice_session).unwrap().unwrap();
        assert_eq!(alice_loaded.msg_send, 1);

        let bob_loaded = store.load_state(&bob_session).unwrap().unwrap();
        assert_eq!(bob_loaded.msg_recv, 1);
    }

    #[test]
    fn test_load_and_continue() {
        let store = test_store();
        let alice_session = [0xAA; 32];
        let bob_session = [0xBB; 32];

        let bob_keypair = InstallationKeyPair::generate();
        let shared_secret = [0x42u8; 32];

        // Initialize and exchange one message
        {
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

            let (ct, header) = alice.encrypt_message(b"Message 1").unwrap();
            bob.decrypt_message(&ct, header).unwrap();
        }

        // Load from storage and continue
        {
            let mut alice: PersistentRatchet<DefaultDomain> =
                PersistentRatchet::load(Arc::clone(&store), alice_session)
                    .unwrap()
                    .unwrap();

            let mut bob: PersistentRatchet<DefaultDomain> =
                PersistentRatchet::load(Arc::clone(&store), bob_session)
                    .unwrap()
                    .unwrap();

            // Bob replies
            let (ct, header) = bob.encrypt_message(b"Reply from Bob").unwrap();
            let pt = alice.decrypt_message(&ct, header).unwrap();
            assert_eq!(pt, b"Reply from Bob");

            // Alice sends another
            let (ct2, header2) = alice.encrypt_message(b"Message 2").unwrap();
            let pt2 = bob.decrypt_message(&ct2, header2).unwrap();
            assert_eq!(pt2, b"Message 2");
        }
    }

    #[test]
    fn test_skipped_keys_persisted() {
        let store = test_store();
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

        let mut bob: PersistentRatchet<DefaultDomain> =
            PersistentRatchet::init_receiver(Arc::clone(&store), bob_session, shared_secret, bob_keypair)
                .unwrap();

        // Alice sends 3 messages
        let mut messages = vec![];
        for i in 0..3 {
            let (ct, header) = alice
                .encrypt_message(format!("Message {}", i).as_bytes())
                .unwrap();
            messages.push((ct, header));
        }

        // Bob receives them out of order: 0, 2 (skipping 1)
        bob.decrypt_message(&messages[0].0, messages[0].1.clone())
            .unwrap();
        bob.decrypt_message(&messages[2].0, messages[2].1.clone())
            .unwrap();

        // Check skipped key was persisted
        let bob_loaded = store.load_state(&bob_session).unwrap().unwrap();
        assert_eq!(bob_loaded.skipped_keys.len(), 1);
        assert_eq!(bob_loaded.skipped_keys[0].msg_num, 1);

        // Now receive the skipped message
        bob.decrypt_message(&messages[1].0, messages[1].1.clone())
            .unwrap();

        // Skipped key should be removed
        let bob_loaded = store.load_state(&bob_session).unwrap().unwrap();
        assert!(bob_loaded.skipped_keys.is_empty());
    }

    #[test]
    fn test_dh_ratchet_persisted() {
        let store = test_store();
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

        let mut bob: PersistentRatchet<DefaultDomain> =
            PersistentRatchet::init_receiver(Arc::clone(&store), bob_session, shared_secret, bob_keypair)
                .unwrap();

        // Alice sends
        let (ct1, h1) = alice.encrypt_message(b"Hello").unwrap();
        bob.decrypt_message(&ct1, h1).unwrap();

        // Get Bob's initial DH public
        let bob_initial_pub = bob.state().dh_self.public().as_bytes().clone();

        // Bob replies (triggers DH ratchet)
        let (ct2, h2) = bob.encrypt_message(b"Hi").unwrap();
        alice.decrypt_message(&ct2, h2).unwrap();

        // Bob's DH key should have changed
        let bob_new_pub = bob.state().dh_self.public().as_bytes().clone();
        assert_ne!(bob_initial_pub, bob_new_pub);

        // Verify persisted
        let bob_loaded = store.load_state(&bob_session).unwrap().unwrap();
        assert_eq!(bob_loaded.dh_self_public, bob_new_pub);
    }

    #[test]
    fn test_delete_session() {
        let store = test_store();
        let session_id = [0x11; 32];
        let bob_keypair = InstallationKeyPair::generate();

        let ratchet: PersistentRatchet<DefaultDomain> = PersistentRatchet::init_sender(
            Arc::clone(&store),
            session_id,
            [0x42u8; 32],
            *bob_keypair.public(),
        )
        .unwrap();

        assert!(store.session_exists(&session_id).unwrap());

        ratchet.delete().unwrap();

        assert!(!store.session_exists(&session_id).unwrap());
    }
}
