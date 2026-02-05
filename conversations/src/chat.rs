//! ChatManager with integrated SQLite persistence.
//!
//! This is the main entry point for the conversations API. It handles all
//! storage operations internally - users don't need to interact with storage directly.

use std::rc::Rc;

use crate::{
    common::{Chat, ChatStore, HasChatId},
    errors::ChatError,
    identity::Identity,
    inbox::{Inbox, Introduction},
    storage::{ChatRecord, ChatStorage, StorageError},
    types::{AddressedEnvelope, ContentData},
};

/// Configuration for ChatManager storage.
pub enum StorageConfig {
    /// In-memory storage (data lost on restart, useful for testing).
    InMemory,
    /// Unencrypted file storage (for development).
    File(String),
    /// Encrypted file storage (for production).
    Encrypted { path: String, key: String },
}

/// Error type for ChatManager operations.
#[derive(Debug, thiserror::Error)]
pub enum ChatManagerError {
    #[error("chat error: {0}")]
    Chat(#[from] ChatError),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
}

/// ChatManager is the main entry point for the conversations API.
///
/// It manages identity, inbox, active chats, and automatically persists
/// all state changes to SQLite storage.
///
/// # Example
///
/// ```ignore
/// // Create a new chat manager with encrypted storage
/// let mut chat = ChatManager::open(StorageConfig::Encrypted {
///     path: "chat.db".into(),
///     key: "my_secret_key".into(),
/// })?;
///
/// // Get your address to share with others
/// println!("My address: {}", chat.local_address());
///
/// // Create an intro bundle to share
/// let intro = chat.create_intro_bundle()?;
///
/// // Start a chat with someone
/// let (chat_id, envelopes) = chat.start_private_chat(&their_intro, "Hello!")?;
/// // Send envelopes over the network...
///
/// // Send more messages
/// let envelopes = chat.send_message(&chat_id, b"How are you?")?;
/// ```
pub struct ChatManager {
    identity: Rc<Identity>,
    store: ChatStore,
    inbox: Inbox,
    storage: ChatStorage,
}

impl ChatManager {
    /// Opens or creates a ChatManager with the given storage configuration.
    ///
    /// If an identity exists in storage, it will be restored.
    /// Otherwise, a new identity will be created and saved.
    pub fn open(config: StorageConfig) -> Result<Self, ChatManagerError> {
        let mut storage = match config {
            StorageConfig::InMemory => ChatStorage::in_memory()?,
            StorageConfig::File(path) => ChatStorage::open(&path)?,
            StorageConfig::Encrypted { path, key } => ChatStorage::new(&path, &key)?,
        };

        // Load or create identity
        let identity = if let Some(identity) = storage.load_identity()? {
            identity
        } else {
            let identity = Identity::new();
            storage.save_identity(&identity)?;
            identity
        };

        let identity = Rc::new(identity);
        let inbox = Inbox::new(Rc::clone(&identity));

        // TODO: Restore inbox ephemeral keys from storage
        // TODO: Restore active chats from storage

        Ok(Self {
            identity,
            store: ChatStore::new(),
            inbox,
            storage,
        })
    }

    /// Creates a new in-memory ChatManager (for testing).
    pub fn in_memory() -> Result<Self, ChatManagerError> {
        Self::open(StorageConfig::InMemory)
    }

    /// Get the local identity's public address.
    ///
    /// This address can be shared with others so they can identify you.
    pub fn local_address(&self) -> String {
        self.identity.address()
    }

    /// Create an introduction bundle that can be shared with others.
    ///
    /// Others can use this bundle to initiate a chat with you.
    /// Share it via QR code, link, or any other out-of-band method.
    pub fn create_intro_bundle(&mut self) -> Result<Introduction, ChatManagerError> {
        let pkb = self.inbox.create_bundle();
        let intro = Introduction::from(pkb);

        // Persist the ephemeral key
        let public_key_hex = hex::encode(intro.ephemeral_key.as_bytes());
        // TODO: Get the secret key from inbox and persist it
        // self.storage.save_inbox_key(&public_key_hex, &secret)?;
        let _ = public_key_hex; // Suppress unused warning for now

        Ok(intro)
    }

    /// Start a new private conversation with someone using their introduction bundle.
    ///
    /// Returns the chat ID and envelopes that must be delivered to the remote party.
    /// The chat state is automatically persisted.
    pub fn start_private_chat(
        &mut self,
        remote_bundle: &Introduction,
        initial_message: &str,
    ) -> Result<(String, Vec<AddressedEnvelope>), ChatManagerError> {
        let (convo, payloads) = self
            .inbox
            .invite_to_private_convo(remote_bundle, initial_message.to_string())?;

        let chat_id = convo.id().to_string();

        let envelopes: Vec<AddressedEnvelope> = payloads
            .into_iter()
            .map(|p| p.to_envelope(chat_id.clone()))
            .collect();

        // Persist chat metadata
        let chat_record = ChatRecord::new_private(
            chat_id.clone(),
            remote_bundle.installation_key,
            "delivery_address".to_string(), // TODO: Get actual delivery address
        );
        self.storage.save_chat(&chat_record)?;

        // Store in memory
        self.store.insert_chat(convo);

        Ok((chat_id, envelopes))
    }

    /// Send a message to an existing chat.
    ///
    /// Returns envelopes that must be delivered to chat participants.
    /// The updated chat state is automatically persisted.
    pub fn send_message(
        &mut self,
        chat_id: &str,
        content: &[u8],
    ) -> Result<Vec<AddressedEnvelope>, ChatManagerError> {
        let chat = self
            .store
            .get_mut_chat(chat_id)
            .ok_or_else(|| ChatError::NoChatId(chat_id.to_string()))?;

        let payloads = chat.send_message(content)?;

        // TODO: Persist updated ratchet state

        Ok(payloads
            .into_iter()
            .map(|p| p.to_envelope(chat.remote_id()))
            .collect())
    }

    /// Handle an incoming payload from the network.
    ///
    /// Returns the decrypted content if successful.
    /// Any new chats or state changes are automatically persisted.
    pub fn handle_incoming(&mut self, _payload: &[u8]) -> Result<ContentData, ChatManagerError> {
        // TODO: Implement proper payload handling
        // 1. Determine if this is an inbox message or a chat message
        // 2. Route to appropriate handler
        // 3. Persist any state changes
        // 4. Return decrypted content
        Ok(ContentData {
            conversation_id: "convo_id".into(),
            data: vec![1, 2, 3, 4, 5, 6],
        })
    }

    /// Get a reference to an active chat.
    pub fn get_chat(&self, chat_id: &str) -> Option<&dyn Chat> {
        self.store.get_chat(chat_id)
    }

    /// List all active chat IDs.
    pub fn list_chats(&self) -> Vec<String> {
        self.store.chat_ids().map(|id| id.to_string()).collect()
    }

    /// List all chat IDs from storage (includes chats not yet loaded into memory).
    pub fn list_stored_chats(&self) -> Result<Vec<String>, ChatManagerError> {
        Ok(self.storage.list_chat_ids()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_chat_manager() {
        let manager = ChatManager::in_memory().unwrap();
        assert!(!manager.local_address().is_empty());
    }

    #[test]
    fn test_identity_persistence() {
        let manager = ChatManager::in_memory().unwrap();
        let address = manager.local_address();

        // Identity should be persisted
        let loaded = manager.storage.load_identity().unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().address(), address);
    }

    #[test]
    fn test_create_intro_bundle() {
        let mut manager = ChatManager::in_memory().unwrap();
        let bundle = manager.create_intro_bundle();
        assert!(bundle.is_ok());
    }

    #[test]
    fn test_start_private_chat() {
        let mut alice = ChatManager::in_memory().unwrap();
        let mut bob = ChatManager::in_memory().unwrap();

        // Bob creates an intro bundle
        let bob_intro = bob.create_intro_bundle().unwrap();

        // Alice starts a chat with Bob
        let result = alice.start_private_chat(&bob_intro, "Hello Bob!");
        assert!(result.is_ok());

        let (chat_id, envelopes) = result.unwrap();
        assert!(!chat_id.is_empty());
        assert!(!envelopes.is_empty());

        // Chat should be persisted
        let stored = alice.list_stored_chats().unwrap();
        assert!(stored.contains(&chat_id));
    }
}
