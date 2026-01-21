use crate::{
    errors::RatchetError,
    hkdf::HkdfInfo,
    state::{Header, RatchetState},
};

use super::{SqliteStorage, StorageError};

/// A session wrapper that automatically persists ratchet state after operations.
/// Provides rollback semantics - state is only saved if the operation succeeds.
pub struct RatchetSession<'a, D: HkdfInfo + Clone> {
    storage: &'a mut SqliteStorage,
    conversation_id: String,
    state: RatchetState<D>,
}

#[derive(Debug)]
pub enum SessionError {
    Storage(StorageError),
    Ratchet(RatchetError),
}

impl From<StorageError> for SessionError {
    fn from(e: StorageError) -> Self {
        SessionError::Storage(e)
    }
}

impl From<RatchetError> for SessionError {
    fn from(e: RatchetError) -> Self {
        SessionError::Ratchet(e)
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::Storage(e) => write!(f, "storage error: {}", e),
            SessionError::Ratchet(e) => write!(f, "ratchet error: {}", e),
        }
    }
}

impl std::error::Error for SessionError {}

impl<'a, D: HkdfInfo + Clone> RatchetSession<'a, D> {
    /// Opens an existing session from storage.
    pub fn open(
        storage: &'a mut SqliteStorage,
        conversation_id: impl Into<String>,
    ) -> Result<Self, StorageError> {
        let conversation_id = conversation_id.into();
        let state = storage.load(&conversation_id)?;
        Ok(Self {
            storage,
            conversation_id,
            state,
        })
    }

    /// Creates a new session and persists the initial state.
    pub fn create(
        storage: &'a mut SqliteStorage,
        conversation_id: impl Into<String>,
        state: RatchetState<D>,
    ) -> Result<Self, StorageError> {
        let conversation_id = conversation_id.into();
        storage.save(&conversation_id, &state)?;
        Ok(Self {
            storage,
            conversation_id,
            state,
        })
    }

    /// Opens an existing session or creates a new one with the provided state.
    pub fn init_session(
        storage: &'a mut SqliteStorage,
        conversation_id: impl Into<String>,
        create_state: impl FnOnce() -> RatchetState<D>,
    ) -> Result<Self, StorageError> {
        let conversation_id = conversation_id.into();
        if storage.exists(&conversation_id)? {
            Self::open(storage, conversation_id)
        } else {
            Self::create(storage, conversation_id, create_state())
        }
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
            return Err(SessionError::Storage(e));
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
                return Err(SessionError::Ratchet(e));
            }
        };

        // Try to persist
        if let Err(e) = self.storage.save(&self.conversation_id, &self.state) {
            // Rollback
            self.state = state_backup;
            return Err(SessionError::Storage(e));
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

    /// Manually saves the current state.
    pub fn save(&mut self) -> Result<(), StorageError> {
        self.storage.save(&self.conversation_id, &self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hkdf::DefaultDomain, keypair::InstallationKeyPair, storage::StorageConfig};

    fn create_test_storage() -> SqliteStorage {
        SqliteStorage::new(StorageConfig::InMemory).unwrap()
    }

    #[test]
    fn test_session_create_and_open() {
        let mut storage = create_test_storage();

        let shared_secret = [0x42; 32];
        let bob_keypair = InstallationKeyPair::generate();
        let alice: RatchetState<DefaultDomain> =
            RatchetState::init_sender(shared_secret, bob_keypair.public().clone());

        // Create session
        {
            let session = RatchetSession::create(&mut storage, "conv1", alice).unwrap();
            assert_eq!(session.conversation_id(), "conv1");
        }

        // Open existing session
        {
            let session: RatchetSession<DefaultDomain> =
                RatchetSession::open(&mut storage, "conv1").unwrap();
            assert_eq!(session.state().msg_send, 0);
        }
    }

    #[test]
    fn test_session_encrypt_persists() {
        let mut storage = create_test_storage();

        let shared_secret = [0x42; 32];
        let bob_keypair = InstallationKeyPair::generate();
        let alice: RatchetState<DefaultDomain> =
            RatchetState::init_sender(shared_secret, bob_keypair.public().clone());

        // Create and encrypt
        {
            let mut session = RatchetSession::create(&mut storage, "conv1", alice).unwrap();
            session.encrypt_message(b"Hello").unwrap();
            assert_eq!(session.state().msg_send, 1);
        }

        // Reopen - state should be persisted
        {
            let session: RatchetSession<DefaultDomain> =
                RatchetSession::open(&mut storage, "conv1").unwrap();
            assert_eq!(session.state().msg_send, 1);
        }
    }

    #[test]
    fn test_session_full_conversation() {
        let mut storage = create_test_storage();

        let shared_secret = [0x42; 32];
        let bob_keypair = InstallationKeyPair::generate();
        let alice: RatchetState<DefaultDomain> =
            RatchetState::init_sender(shared_secret, bob_keypair.public().clone());
        let bob: RatchetState<DefaultDomain> =
            RatchetState::init_receiver(shared_secret, bob_keypair);

        // Alice sends
        let (ct, header) = {
            let mut session = RatchetSession::create(&mut storage, "alice", alice).unwrap();
            session.encrypt_message(b"Hello Bob").unwrap()
        };

        // Bob receives
        let plaintext = {
            let mut session = RatchetSession::create(&mut storage, "bob", bob).unwrap();
            session.decrypt_message(&ct, header).unwrap()
        };
        assert_eq!(plaintext, b"Hello Bob");

        // Bob replies
        let (ct2, header2) = {
            let mut session: RatchetSession<DefaultDomain> =
                RatchetSession::open(&mut storage, "bob").unwrap();
            session.encrypt_message(b"Hi Alice").unwrap()
        };

        // Alice receives
        let plaintext2 = {
            let mut session: RatchetSession<DefaultDomain> =
                RatchetSession::open(&mut storage, "alice").unwrap();
            session.decrypt_message(&ct2, header2).unwrap()
        };
        assert_eq!(plaintext2, b"Hi Alice");
    }

    #[test]
    fn test_session_open_or_create() {
        let mut storage = create_test_storage();

        let shared_secret = [0x42; 32];
        let bob_keypair = InstallationKeyPair::generate();
        let bob_pub = bob_keypair.public().clone();

        // First call creates
        {
            let session: RatchetSession<DefaultDomain> =
                RatchetSession::init_session(&mut storage, "conv1", || {
                    RatchetState::init_sender(shared_secret, bob_pub.clone())
                })
                .unwrap();
            assert_eq!(session.state().msg_send, 0);
        }

        // Second call opens existing
        {
            let mut session: RatchetSession<DefaultDomain> =
                RatchetSession::init_session(&mut storage, "conv1", || {
                    panic!("should not be called")
                })
                .unwrap();
            session.encrypt_message(b"test").unwrap();
        }

        // Verify persistence
        {
            let session: RatchetSession<DefaultDomain> =
                RatchetSession::open(&mut storage, "conv1").unwrap();
            assert_eq!(session.state().msg_send, 1);
        }
    }
}
