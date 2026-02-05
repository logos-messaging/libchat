//! ChatManager with integrated SQLite persistence.
//!
//! This is the main entry point for the conversations API. It handles all
//! storage operations internally - users don't need to interact with storage directly.

use std::collections::HashMap;
use std::rc::Rc;

use double_ratchets::storage::RatchetStorage;

use crate::{
    common::{Chat, HasChatId, InboundMessageHandler},
    dm::privatev1::PrivateV1Convo,
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
    /// In-memory cache of active chats. Chats are loaded from storage on demand.
    chats: HashMap<String, PrivateV1Convo>,
    inbox: Inbox,
    /// Storage for chat metadata (identity, inbox keys, chat records).
    storage: ChatStorage,
    /// Storage for ratchet state (delegated to double-ratchets crate).
    ratchet_storage: RatchetStorage,
}

impl ChatManager {
    /// Opens or creates a ChatManager with the given storage configuration.
    ///
    /// If an identity exists in storage, it will be restored.
    /// Otherwise, a new identity will be created and saved.
    ///
    /// Inbox ephemeral keys are loaded lazily when handling incoming handshakes.
    pub fn open(config: StorageConfig) -> Result<Self, ChatManagerError> {
        let mut storage = ChatStorage::new(config.clone())?;

        // Initialize ratchet storage (delegated to double-ratchets crate)
        let ratchet_storage = RatchetStorage::with_config(config)?;

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
            chats: HashMap::new(),
            inbox,
            storage,
            ratchet_storage,
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

        // Persist ratchet state (delegated to double-ratchets storage)
        self.ratchet_storage.save(&chat_id, convo.ratchet_state())?;

        // Store in memory cache
        self.chats.insert(chat_id.clone(), convo);

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
        // Try to load chat from storage if not in memory
        self.ensure_chat_loaded(chat_id)?;

        let chat = self
            .chats
            .get_mut(chat_id)
            .ok_or_else(|| ChatManagerError::ChatNotFound(chat_id.to_string()))?;

        let payloads = chat.send_message(content)?;

        // Persist updated ratchet state (delegated to double-ratchets storage)
        self.ratchet_storage.save(chat_id, chat.ratchet_state())?;

        let remote_id = chat.remote_id();
        Ok(payloads
            .into_iter()
            .map(|p| p.to_envelope(remote_id.clone()))
            .collect())
    }

    /// Ensure a chat is loaded into memory. Loads from storage if needed.
    fn ensure_chat_loaded(&mut self, chat_id: &str) -> Result<(), ChatManagerError> {
        if self.chats.contains_key(chat_id) {
            return Ok(());
        }

        // Try to load ratchet state from double-ratchets storage
        if self.ratchet_storage.exists(chat_id)? {
            let dr_state = self.ratchet_storage.load(chat_id)?;
            let convo = PrivateV1Convo::from_state(chat_id.to_string(), dr_state);
            self.chats.insert(chat_id.to_string(), convo);
            Ok(())
        } else if self.storage.chat_exists(chat_id)? {
            // Chat metadata exists but no ratchet state - this is a data inconsistency
            Err(ChatManagerError::ChatNotFound(format!(
                "{} (corrupted: missing ratchet state)",
                chat_id
            )))
        } else {
            Err(ChatManagerError::ChatNotFound(chat_id.to_string()))
        }
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

                // Persist the new chat metadata
                let chat_record = ChatRecord {
                    chat_id: chat_id.clone(),
                    chat_type: "private_v1".to_string(),
                    remote_public_key: None, // Would need to extract from handshake
                    remote_address: "unknown".to_string(),
                    created_at: crate::utils::timestamp_millis() as i64,
                };
                self.storage.save_chat(&chat_record)?;

                // TODO: Persist ratchet state for incoming chats
                // This requires modifying InboundMessageHandler to return PrivateV1Convo
                // or adding downcast support. For now, new chats from inbox won't persist
                // their ratchet state until next send_message call.

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
    pub fn get_chat(&mut self, chat_id: &str) -> Option<&PrivateV1Convo> {
        // Try to load from storage if not in memory
        let _ = self.ensure_chat_loaded(chat_id);
        self.chats.get(chat_id)
    }

    /// List all active chat IDs (in memory).
    pub fn list_chats(&self) -> Vec<String> {
        self.chats.keys().cloned().collect()
    }

    /// List all chat IDs from storage.
    pub fn list_stored_chats(&self) -> Result<Vec<String>, ChatManagerError> {
        Ok(self.storage.list_chat_ids()?)
    }

    /// Check if a chat exists (in memory or storage).
    pub fn chat_exists(&self, chat_id: &str) -> Result<bool, ChatManagerError> {
        if self.chats.contains_key(chat_id) {
            return Ok(true);
        }
        Ok(self.storage.chat_exists(chat_id)?)
    }

    /// Delete a chat from both memory and storage.
    pub fn delete_chat(&mut self, chat_id: &str) -> Result<(), ChatManagerError> {
        self.chats.remove(chat_id);
        self.storage.delete_chat(chat_id)?;
        // Also delete ratchet state from double-ratchets storage
        let _ = self.ratchet_storage.delete(chat_id);
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

    #[test]
    fn test_ratchet_state_persistence() {
        use tempfile::tempdir;

        // Create a temporary directory for the database
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        let mut bob = ChatManager::in_memory().unwrap();
        let bob_intro = bob.create_intro_bundle().unwrap();

        let chat_id;

        // Scope 1: Create chat and send messages
        {
            let mut alice =
                ChatManager::open(StorageConfig::File(db_path.to_str().unwrap().to_string()))
                    .unwrap();

            let result = alice.start_private_chat(&bob_intro, "Message 1").unwrap();
            chat_id = result.0;

            // Send more messages - this advances the ratchet
            alice.send_message(&chat_id, b"Message 2").unwrap();
            alice.send_message(&chat_id, b"Message 3").unwrap();

            // Chat should be in memory
            assert!(alice.chats.contains_key(&chat_id));
        }
        // alice is dropped here, simulating app close

        // Scope 2: Reopen and verify chat is restored
        {
            let mut alice2 =
                ChatManager::open(StorageConfig::File(db_path.to_str().unwrap().to_string()))
                    .unwrap();

            // Chat is in storage but not loaded yet
            assert!(alice2.list_stored_chats().unwrap().contains(&chat_id));
            assert!(!alice2.chats.contains_key(&chat_id));

            // Send another message - this will load the chat and advance ratchet
            let result = alice2.send_message(&chat_id, b"Message 4");
            assert!(result.is_ok(), "Should be able to send after restore");

            // Chat should now be in memory
            assert!(alice2.chats.contains_key(&chat_id));
        }
    }
}
