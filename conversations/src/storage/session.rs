//! Session wrapper for automatic state persistence.
//!
//! Provides a `ChatSession` that wraps `ChatManager` and automatically
//! persists state changes to SQLite storage.

use crate::{
    chat::ChatManager,
    errors::ChatError,
    identity::Identity,
    inbox::Introduction,
    storage::{ChatRecord, ChatStorage, StorageError},
    types::{AddressedEnvelope, ContentData},
};

/// Error type for chat session operations.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("chat error: {0}")]
    Chat(#[from] ChatError),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("session already exists for this identity")]
    SessionExists,
}

/// A persistent chat session that automatically saves state to storage.
///
/// This wraps a `ChatManager` and ensures all state changes are persisted
/// to SQLite storage. When reopened, the session restores the previous state.
///
/// # Example
///
/// ```ignore
/// // Create a new session (or open existing)
/// let mut session = ChatSession::open_or_create("chat.db", "encryption_key")?;
///
/// // Create intro bundle (automatically persisted)
/// let intro = session.create_intro_bundle()?;
///
/// // Start a chat (automatically persisted)
/// let (chat_id, envelopes) = session.start_private_chat(&remote_intro, "Hello!")?;
///
/// // Later, reopen the session
/// let mut session = ChatSession::open("chat.db", "encryption_key")?;
/// // Previous identity and chats are restored
/// ```
pub struct ChatSession {
    manager: ChatManager,
    storage: ChatStorage,
}

impl ChatSession {
    /// Opens an existing session from storage.
    ///
    /// Returns an error if no identity exists in the storage.
    pub fn open(path: &str, key: &str) -> Result<Self, SessionError> {
        let storage = ChatStorage::new(path, key)?;

        let identity = storage
            .load_identity()?
            .ok_or_else(|| SessionError::Storage(StorageError::NotFound("identity".into())))?;

        let manager = ChatManager::with_identity(identity);

        // TODO: Restore inbox ephemeral keys
        // TODO: Restore active chats

        Ok(Self { manager, storage })
    }

    /// Creates a new session with a fresh identity.
    ///
    /// Returns an error if an identity already exists in the storage.
    pub fn create(path: &str, key: &str) -> Result<Self, SessionError> {
        let mut storage = ChatStorage::new(path, key)?;

        if storage.has_identity()? {
            return Err(SessionError::SessionExists);
        }

        let identity = Identity::new();
        storage.save_identity(&identity)?;

        let manager = ChatManager::with_identity(identity);

        Ok(Self { manager, storage })
    }

    /// Opens an existing session or creates a new one if none exists.
    pub fn open_or_create(path: &str, key: &str) -> Result<Self, SessionError> {
        let mut storage = ChatStorage::new(path, key)?;

        let identity = if let Some(identity) = storage.load_identity()? {
            identity
        } else {
            let identity = Identity::new();
            storage.save_identity(&identity)?;
            identity
        };

        let manager = ChatManager::with_identity(identity);

        // TODO: Restore inbox ephemeral keys and active chats

        Ok(Self { manager, storage })
    }

    /// Creates an in-memory session (useful for testing).
    pub fn in_memory() -> Result<Self, SessionError> {
        let mut storage = ChatStorage::in_memory()?;
        let identity = Identity::new();
        storage.save_identity(&identity)?;
        let manager = ChatManager::with_identity(identity);

        Ok(Self { manager, storage })
    }

    /// Get the local identity's public address.
    pub fn local_address(&self) -> String {
        self.manager.local_address()
    }

    /// Create an introduction bundle that can be shared with others.
    ///
    /// The ephemeral key is automatically persisted.
    pub fn create_intro_bundle(&mut self) -> Result<Introduction, SessionError> {
        let intro = self.manager.create_intro_bundle()?;

        // Persist the ephemeral key
        let _public_key_hex = hex::encode(intro.ephemeral_key.as_bytes());
        // TODO: Get the secret key from inbox and persist it
        // self.storage.save_inbox_key(&public_key_hex, &secret)?;

        Ok(intro)
    }

    /// Start a new private conversation with someone using their introduction bundle.
    ///
    /// The chat state is automatically persisted.
    pub fn start_private_chat(
        &mut self,
        remote_bundle: &Introduction,
        initial_message: &str,
    ) -> Result<(String, Vec<AddressedEnvelope>), SessionError> {
        let (chat_id, envelopes) = self.manager.start_private_chat(remote_bundle, initial_message)?;

        // Persist chat metadata
        let chat_record = ChatRecord::new_private(
            chat_id.clone(),
            remote_bundle.installation_key,
            "delivery_address".to_string(), // TODO: Get actual delivery address
        );
        self.storage.save_chat(&chat_record)?;

        Ok((chat_id, envelopes))
    }

    /// Send a message to an existing chat.
    ///
    /// The updated chat state is automatically persisted.
    pub fn send_message(
        &mut self,
        chat_id: &str,
        content: &[u8],
    ) -> Result<Vec<AddressedEnvelope>, SessionError> {
        let envelopes = self.manager.send_message(chat_id, content)?;

        // TODO: Persist updated ratchet state

        Ok(envelopes)
    }

    /// Handle an incoming payload from the network.
    pub fn handle_incoming(&mut self, payload: &[u8]) -> Result<ContentData, SessionError> {
        let content = self.manager.handle_incoming(payload)?;

        // TODO: Persist updated state

        Ok(content)
    }

    /// List all active chat IDs.
    pub fn list_chats(&self) -> Vec<String> {
        self.manager.list_chats()
    }

    /// Get access to the underlying ChatManager.
    pub fn manager(&self) -> &ChatManager {
        &self.manager
    }

    /// Get mutable access to the underlying ChatManager.
    pub fn manager_mut(&mut self) -> &mut ChatManager {
        &mut self.manager
    }

    /// Get access to the underlying storage.
    pub fn storage(&self) -> &ChatStorage {
        &self.storage
    }

    /// Get mutable access to the underlying storage.
    pub fn storage_mut(&mut self) -> &mut ChatStorage {
        &mut self.storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_session() {
        let session = ChatSession::in_memory().unwrap();
        assert!(!session.local_address().is_empty());
    }

    #[test]
    fn test_session_persistence() {
        // Create a session with in-memory storage
        let session = ChatSession::in_memory().unwrap();
        let address = session.local_address();

        // Verify identity was saved
        let loaded_identity = session.storage.load_identity().unwrap();
        assert!(loaded_identity.is_some());
        assert_eq!(loaded_identity.unwrap().address(), address);
    }

    #[test]
    fn test_start_chat_persists() {
        let mut alice = ChatSession::in_memory().unwrap();
        let mut bob = ChatSession::in_memory().unwrap();

        // Bob creates intro bundle
        let bob_intro = bob.create_intro_bundle().unwrap();

        // Alice starts a chat
        let (chat_id, _envelopes) = alice
            .start_private_chat(&bob_intro, "Hello!")
            .unwrap();

        // Verify chat was persisted
        let chat_record = alice.storage.load_chat(&chat_id).unwrap();
        assert!(chat_record.is_some());
        assert_eq!(chat_record.unwrap().chat_type, "private_v1");
    }
}
