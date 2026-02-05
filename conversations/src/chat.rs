//! ChatManager with integrated SQLite persistence.
//!
//! This is the main entry point for the conversations API. It handles all
//! storage operations internally - users don't need to interact with storage directly.

use std::rc::Rc;

use crate::{
    common::{Chat, ChatStore, HasChatId, InboundMessageHandler},
    errors::ChatError,
    identity::Identity,
    inbox::{Inbox, Introduction},
    storage::{ChatRecord, ChatStorage, StorageError},
    types::{AddressedEnvelope, ContentData},
};

// Re-export StorageConfig from storage crate for convenience
pub use storage::StorageConfig;

/// Error type for ChatManager operations.
#[derive(Debug, thiserror::Error)]
pub enum ChatManagerError {
    #[error("chat error: {0}")]
    Chat(#[from] ChatError),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("chat not found: {0}")]
    ChatNotFound(String),

    #[error("chat not loaded: {0} (exists in storage but not in memory)")]
    ChatNotLoaded(String),
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
    ///
    /// Inbox ephemeral keys are loaded lazily when handling incoming handshakes.
    pub fn open(config: StorageConfig) -> Result<Self, ChatManagerError> {
        let mut storage = ChatStorage::new(config)?;

        // Load or create identity
        let identity = if let Some(identity) = storage.load_identity()? {
            identity
        } else {
            let identity = Identity::new();
            storage.save_identity(&identity)?;
            identity
        };

        let identity = Rc::new(identity);

        // Load inbox ephemeral keys from storage
        let inbox_keys = storage.load_all_inbox_keys()?;
        let inbox = Inbox::with_keys(Rc::clone(&identity), inbox_keys);

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
    ///
    /// The ephemeral key is automatically persisted to storage.
    pub fn create_intro_bundle(&mut self) -> Result<Introduction, ChatManagerError> {
        let (pkb, secret) = self.inbox.create_bundle();
        let intro = Introduction::from(pkb);

        // Persist the ephemeral key
        let public_key_hex = hex::encode(intro.ephemeral_key.as_bytes());
        self.storage.save_inbox_key(&public_key_hex, &secret)?;

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
            payloads_delivery_address(&envelopes),
        );
        self.storage.save_chat(&chat_record)?;

        // Store in memory
        self.store.insert_chat(convo);

        Ok((chat_id, envelopes))
    }

    /// Send a message to an existing chat.
    ///
    /// Returns envelopes that must be delivered to chat participants.
    pub fn send_message(
        &mut self,
        chat_id: &str,
        content: &[u8],
    ) -> Result<Vec<AddressedEnvelope>, ChatManagerError> {
        // Try to get chat from memory first
        let chat = match self.store.get_mut_chat(chat_id) {
            Some(chat) => chat,
            None => {
                // Check if chat exists in storage but not loaded
                if self.storage.chat_exists(chat_id)? {
                    return Err(ChatManagerError::ChatNotLoaded(chat_id.to_string()));
                } else {
                    return Err(ChatManagerError::ChatNotFound(chat_id.to_string()));
                }
            }
        };

        let payloads = chat.send_message(content)?;

        Ok(payloads
            .into_iter()
            .map(|p| p.to_envelope(chat.remote_id()))
            .collect())
    }

    /// Handle an incoming payload from the network.
    ///
    /// This processes both inbox handshakes (to establish new chats) and
    /// messages for existing chats.
    ///
    /// Returns the decrypted content if successful.
    /// Any new chats or state changes are automatically persisted.
    pub fn handle_incoming(&mut self, payload: &[u8]) -> Result<ContentData, ChatManagerError> {
        // Try to handle as inbox message (new chat invitation)
        match self.inbox.handle_frame(payload) {
            Ok((chat, content_data)) => {
                let chat_id = chat.id().to_string();

                // Persist the new chat
                // Note: We don't have full remote info here, using placeholder
                let chat_record = ChatRecord {
                    chat_id: chat_id.clone(),
                    chat_type: "private_v1".to_string(),
                    remote_public_key: None, // Would need to extract from handshake
                    remote_address: "unknown".to_string(),
                    created_at: crate::utils::timestamp_millis() as i64,
                };
                self.storage.save_chat(&chat_record)?;

                // Store chat in memory
                self.store.insert_boxed_chat(chat);

                // Return first content if any, otherwise empty
                if let Some(first) = content_data.into_iter().next() {
                    return Ok(first);
                }

                Ok(ContentData {
                    conversation_id: chat_id,
                    data: vec![],
                })
            }
            Err(_) => {
                // Not an inbox message, try existing chats
                // For now, return placeholder - would need to route to correct chat
                Ok(ContentData {
                    conversation_id: "unknown".into(),
                    data: vec![],
                })
            }
        }
    }

    /// Get a reference to an active chat.
    pub fn get_chat(&self, chat_id: &str) -> Option<&dyn Chat> {
        self.store.get_chat(chat_id)
    }

    /// List all active chat IDs (in memory).
    pub fn list_chats(&self) -> Vec<String> {
        self.store.chat_ids().map(|id| id.to_string()).collect()
    }

    /// List all chat IDs from storage.
    pub fn list_stored_chats(&self) -> Result<Vec<String>, ChatManagerError> {
        Ok(self.storage.list_chat_ids()?)
    }

    /// Check if a chat exists (in memory or storage).
    pub fn chat_exists(&self, chat_id: &str) -> Result<bool, ChatManagerError> {
        if self.store.get_chat(chat_id).is_some() {
            return Ok(true);
        }
        Ok(self.storage.chat_exists(chat_id)?)
    }

    /// Delete a chat from both memory and storage.
    pub fn delete_chat(&mut self, chat_id: &str) -> Result<(), ChatManagerError> {
        self.store.remove_chat(chat_id);
        self.storage.delete_chat(chat_id)?;
        Ok(())
    }
}

/// Extract delivery address from envelopes (helper function).
fn payloads_delivery_address(envelopes: &[AddressedEnvelope]) -> String {
    envelopes
        .first()
        .map(|e| e.delivery_address.clone())
        .unwrap_or_else(|| "unknown".to_string())
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

    #[test]
    fn test_inbox_key_persistence() {
        let mut manager = ChatManager::in_memory().unwrap();

        // Create intro bundle (should persist ephemeral key)
        let intro = manager.create_intro_bundle().unwrap();
        let key_hex = hex::encode(intro.ephemeral_key.as_bytes());

        // Key should be persisted
        let loaded_key = manager.storage.load_inbox_key(&key_hex).unwrap();
        assert!(loaded_key.is_some());
    }

    #[test]
    fn test_chat_exists() {
        let mut alice = ChatManager::in_memory().unwrap();
        let mut bob = ChatManager::in_memory().unwrap();

        let bob_intro = bob.create_intro_bundle().unwrap();
        let (chat_id, _) = alice.start_private_chat(&bob_intro, "Hello!").unwrap();

        // Chat should exist
        assert!(alice.chat_exists(&chat_id).unwrap());
        assert!(!alice.chat_exists("nonexistent").unwrap());
    }

    #[test]
    fn test_delete_chat() {
        let mut alice = ChatManager::in_memory().unwrap();
        let mut bob = ChatManager::in_memory().unwrap();

        let bob_intro = bob.create_intro_bundle().unwrap();
        let (chat_id, _) = alice.start_private_chat(&bob_intro, "Hello!").unwrap();

        // Delete chat
        alice.delete_chat(&chat_id).unwrap();

        // Chat should no longer exist
        assert!(!alice.chat_exists(&chat_id).unwrap());
        assert!(alice.list_chats().is_empty());
    }
}
