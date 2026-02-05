//! Session wrapper for automatic state persistence.

use storage::StorageConfig;
use x25519_dalek::PublicKey;

use crate::{
    InstallationKeyPair, SessionError,
    hkdf::{DefaultDomain, HkdfInfo},
    state::{Header, RatchetState},
    types::SharedSecret,
};

use super::RatchetStorage;

/// A session wrapper that automatically persists ratchet state after operations.
/// Provides rollback semantics - state is only saved if the operation succeeds.
///
/// This struct owns its storage, making it easy to store in other structs
/// and use across multiple operations without lifetime concerns.
pub struct RatchetSession<D: HkdfInfo + Clone = DefaultDomain> {
    storage: RatchetStorage,
    conversation_id: String,
    state: RatchetState<D>,
}

impl<D: HkdfInfo + Clone> RatchetSession<D> {
    /// Opens an existing session from storage.
    pub fn open(
        storage: RatchetStorage,
        conversation_id: impl Into<String>,
    ) -> Result<Self, SessionError> {
        let conversation_id = conversation_id.into();
        let state = storage.load(&conversation_id)?;
        Ok(Self {
            storage,
            conversation_id,
            state,
        })
    }

    /// Opens an existing session with the given storage configuration.
    pub fn open_with_config(
        config: StorageConfig,
        conversation_id: impl Into<String>,
    ) -> Result<Self, SessionError> {
        let storage = RatchetStorage::with_config(config)?;
        Self::open(storage, conversation_id)
    }

    /// Creates a new session and persists the initial state.
    pub fn create(
        mut storage: RatchetStorage,
        conversation_id: impl Into<String>,
        state: RatchetState<D>,
    ) -> Result<Self, SessionError> {
        let conversation_id = conversation_id.into();
        storage.save(&conversation_id, &state)?;
        Ok(Self {
            storage,
            conversation_id,
            state,
        })
    }

    /// Creates a new session with the given storage configuration.
    pub fn create_with_config(
        config: StorageConfig,
        conversation_id: impl Into<String>,
        state: RatchetState<D>,
    ) -> Result<Self, SessionError> {
        let storage = RatchetStorage::with_config(config)?;
        Self::create(storage, conversation_id, state)
    }

    /// Initializes a new session as a sender and persists the initial state.
    pub fn create_sender_session(
        storage: RatchetStorage,
        conversation_id: &str,
        shared_secret: SharedSecret,
        remote_pub: PublicKey,
    ) -> Result<Self, SessionError> {
        if storage.exists(conversation_id)? {
            return Err(SessionError::ConvAlreadyExists(conversation_id.to_string()));
        }
        let state = RatchetState::<D>::init_sender(shared_secret, remote_pub);
        Self::create(storage, conversation_id, state)
    }

    /// Initializes a new session as a receiver and persists the initial state.
    pub fn create_receiver_session(
        storage: RatchetStorage,
        conversation_id: &str,
        shared_secret: SharedSecret,
        dh_self: InstallationKeyPair,
    ) -> Result<Self, SessionError> {
        if storage.exists(conversation_id)? {
            return Err(SessionError::ConvAlreadyExists(conversation_id.to_string()));
        }

        let state = RatchetState::<D>::init_receiver(shared_secret, dh_self);
        Self::create(storage, conversation_id, state)
    }

    /// Encrypts a message and persists the updated state.
    /// If persistence fails, the in-memory state is NOT modified.
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, Header), SessionError> {
        // Clone state for rollback
        let state_backup = self.state.clone();

        // Perform encryption (modifies state)
        let result = self.state.encrypt_message(plaintext);

        // Try to persist
        if let Err(e) = self.storage.save(&self.conversation_id, &self.state) {
            // Rollback
            self.state = state_backup;
            return Err(e.into());
        }

        Ok(result)
    }

    /// Decrypts a message and persists the updated state.
    /// If decryption or persistence fails, the in-memory state is NOT modified.
    pub fn decrypt_message(
        &mut self,
        ciphertext_with_nonce: &[u8],
        header: Header,
    ) -> Result<Vec<u8>, SessionError> {
        // Clone state for rollback
        let state_backup = self.state.clone();

        // Perform decryption (modifies state)
        let plaintext = match self.state.decrypt_message(ciphertext_with_nonce, header) {
            Ok(pt) => pt,
            Err(e) => {
                // Rollback on decrypt failure
                self.state = state_backup;
                return Err(e.into());
            }
        };

        // Try to persist
        if let Err(e) = self.storage.save(&self.conversation_id, &self.state) {
            // Rollback
            self.state = state_backup;
            return Err(e.into());
        }

        Ok(plaintext)
    }

    /// Returns a reference to the current state (read-only).
    pub fn state(&self) -> &RatchetState<D> {
        &self.state
    }

    /// Returns the conversation ID.
    pub fn conversation_id(&self) -> &str {
        &self.conversation_id
    }

    /// Consumes the session and returns the underlying storage.
    /// Useful when you need to reuse the storage for another session.
    pub fn into_storage(self) -> RatchetStorage {
        self.storage
    }

    /// Manually saves the current state.
    pub fn save(&mut self) -> Result<(), SessionError> {
        self.storage
            .save(&self.conversation_id, &self.state)
            .map_err(|error| error.into())
    }

    pub fn msg_send(&self) -> u32 {
        self.state.msg_send
    }

    pub fn msg_recv(&self) -> u32 {
        self.state.msg_recv
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hkdf::DefaultDomain;

    fn create_test_storage() -> RatchetStorage {
        RatchetStorage::in_memory().unwrap()
    }

    #[test]
    fn test_session_create_and_open() {
        let storage = create_test_storage();

        let shared_secret = [0x42; 32];
        let bob_keypair = InstallationKeyPair::generate();
        let alice: RatchetState<DefaultDomain> =
            RatchetState::init_sender(shared_secret, bob_keypair.public().clone());

        // Create session - session takes ownership of storage
        let session = RatchetSession::create(storage, "conv1", alice).unwrap();
        assert_eq!(session.conversation_id(), "conv1");

        // Get storage back from session to reopen
        let storage = session.into_storage();

        // Open existing session
        let session: RatchetSession<DefaultDomain> =
            RatchetSession::open(storage, "conv1").unwrap();
        assert_eq!(session.state().msg_send, 0);
    }

    #[test]
    fn test_session_encrypt_persists() {
        let storage = create_test_storage();

        let shared_secret = [0x42; 32];
        let bob_keypair = InstallationKeyPair::generate();
        let alice: RatchetState<DefaultDomain> =
            RatchetState::init_sender(shared_secret, bob_keypair.public().clone());

        // Create and encrypt
        let mut session = RatchetSession::create(storage, "conv1", alice).unwrap();
        session.encrypt_message(b"Hello").unwrap();
        assert_eq!(session.state().msg_send, 1);

        // Get storage back and reopen
        let storage = session.into_storage();

        // Reopen - state should be persisted
        let session: RatchetSession<DefaultDomain> =
            RatchetSession::open(storage, "conv1").unwrap();
        assert_eq!(session.state().msg_send, 1);
    }

    #[test]
    fn test_session_full_conversation() {
        // Use separate in-memory storages for alice and bob (simulates different devices)
        let alice_storage = create_test_storage();
        let bob_storage = create_test_storage();

        let shared_secret = [0x42; 32];
        let bob_keypair = InstallationKeyPair::generate();
        let alice_state: RatchetState<DefaultDomain> =
            RatchetState::init_sender(shared_secret, bob_keypair.public().clone());
        let bob_state: RatchetState<DefaultDomain> =
            RatchetState::init_receiver(shared_secret, bob_keypair);

        // Alice sends
        let mut alice_session = RatchetSession::create(alice_storage, "conv", alice_state).unwrap();
        let (ct, header) = alice_session.encrypt_message(b"Hello Bob").unwrap();

        // Bob receives
        let mut bob_session = RatchetSession::create(bob_storage, "conv", bob_state).unwrap();
        let plaintext = bob_session.decrypt_message(&ct, header).unwrap();
        assert_eq!(plaintext, b"Hello Bob");

        // Bob replies
        let (ct2, header2) = bob_session.encrypt_message(b"Hi Alice").unwrap();

        // Alice receives
        let plaintext2 = alice_session.decrypt_message(&ct2, header2).unwrap();
        assert_eq!(plaintext2, b"Hi Alice");
    }

    #[test]
    fn test_session_open_or_create() {
        let storage = create_test_storage();

        let shared_secret = [0x42; 32];
        let bob_keypair = InstallationKeyPair::generate();
        let bob_pub = bob_keypair.public().clone();

        // First call creates
        let session: RatchetSession<DefaultDomain> =
            RatchetSession::create_sender_session(storage, "conv1", shared_secret, bob_pub.clone())
                .unwrap();
        assert_eq!(session.state().msg_send, 0);
        let storage = session.into_storage();

        // Second call opens existing and encrypts
        let mut session: RatchetSession<DefaultDomain> =
            RatchetSession::open(storage, "conv1").unwrap();
        session.encrypt_message(b"test").unwrap();
        let storage = session.into_storage();

        // Verify persistence
        let session: RatchetSession<DefaultDomain> =
            RatchetSession::open(storage, "conv1").unwrap();
        assert_eq!(session.state().msg_send, 1);
    }

    #[test]
    fn test_create_sender_session_fails_when_conversation_exists() {
        let storage = create_test_storage();

        let shared_secret = [0x42; 32];
        let bob_keypair = InstallationKeyPair::generate();
        let bob_pub = bob_keypair.public().clone();

        // First creation succeeds
        let session: RatchetSession<DefaultDomain> =
            RatchetSession::create_sender_session(storage, "conv1", shared_secret, bob_pub.clone())
                .unwrap();
        let storage = session.into_storage();

        // Second creation should fail with ConversationAlreadyExists
        let result: Result<RatchetSession<DefaultDomain>, _> =
            RatchetSession::create_sender_session(storage, "conv1", shared_secret, bob_pub.clone());

        assert!(matches!(result, Err(SessionError::ConvAlreadyExists(_))));
    }

    #[test]
    fn test_create_receiver_session_fails_when_conversation_exists() {
        let storage = create_test_storage();

        let shared_secret = [0x42; 32];
        let bob_keypair = InstallationKeyPair::generate();

        // First creation succeeds
        let session: RatchetSession<DefaultDomain> =
            RatchetSession::create_receiver_session(storage, "conv1", shared_secret, bob_keypair)
                .unwrap();
        let storage = session.into_storage();

        // Second creation should fail with ConversationAlreadyExists
        let another_keypair = InstallationKeyPair::generate();
        let result: Result<RatchetSession<DefaultDomain>, _> =
            RatchetSession::create_receiver_session(
                storage,
                "conv1",
                shared_secret,
                another_keypair,
            );

        assert!(matches!(result, Err(SessionError::ConvAlreadyExists(_))));
    }
}
