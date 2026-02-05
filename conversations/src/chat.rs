//! ChatManager with integrated SQLite persistence.
//!
//! This is the main entry point for the conversations API. It handles all
//! storage operations internally - users don't need to interact with storage directly.

use std::rc::Rc;

use double_ratchets::storage::RatchetStorage;
use prost::Message;

use crate::{
    common::{Chat, HasChatId, InboundMessageHandler},
    dm::privatev1::PrivateV1Convo,
    errors::ChatError,
    identity::Identity,
    inbox::{Inbox, Introduction},
    proto,
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
}

/// ChatManager is the main entry point for the conversations API.
///
/// It manages identity, inbox, and chats with all state persisted to SQLite.
/// Chats are loaded from storage on each operation - no in-memory caching.
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
    inbox: Inbox,
    /// Storage for chat metadata (identity, inbox keys, chat records).
    storage: ChatStorage,
    /// Storage config for creating ratchet storage instances.
    storage_config: StorageConfig,
}

impl ChatManager {
    /// Opens or creates a ChatManager with the given storage configuration.
    ///
    /// If an identity exists in storage, it will be restored.
    /// Otherwise, a new identity will be created and saved.
    pub fn open(config: StorageConfig) -> Result<Self, ChatManagerError> {
        let mut storage = ChatStorage::new(config.clone())?;

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
            inbox,
            storage,
            storage_config: config,
        })
    }

    /// Creates a new in-memory ChatManager (for testing).
    pub fn in_memory() -> Result<Self, ChatManagerError> {
        Self::open(StorageConfig::InMemory)
    }

    /// Creates a new RatchetStorage instance using the stored config.
    fn create_ratchet_storage(&self) -> Result<RatchetStorage, ChatManagerError> {
        Ok(RatchetStorage::with_config(self.storage_config.clone())?)
    }

    /// Load a chat from storage.
    fn load_chat(&self, chat_id: &str) -> Result<PrivateV1Convo, ChatManagerError> {
        let ratchet_storage = self.create_ratchet_storage()?;
        if ratchet_storage.exists(chat_id)? {
            Ok(PrivateV1Convo::open(ratchet_storage, chat_id.to_string())?)
        } else if self.storage.chat_exists(chat_id)? {
            // Chat metadata exists but no ratchet state - data inconsistency
            Err(ChatManagerError::ChatNotFound(format!(
                "{} (corrupted: missing ratchet state)",
                chat_id
            )))
        } else {
            Err(ChatManagerError::ChatNotFound(chat_id.to_string()))
        }
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
    /// The chat state is automatically persisted (via RatchetSession).
    pub fn start_private_chat(
        &mut self,
        remote_bundle: &Introduction,
        initial_message: &str,
    ) -> Result<(String, Vec<AddressedEnvelope>), ChatManagerError> {
        // Create new storage for this conversation's RatchetSession
        let ratchet_storage = self.create_ratchet_storage()?;

        let (convo, payloads) = self.inbox.invite_to_private_convo(
            ratchet_storage,
            remote_bundle,
            initial_message.to_string(),
        )?;

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

        // Ratchet state is automatically persisted by RatchetSession
        // convo is dropped here - state already saved

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
        // Load chat from storage
        let mut chat = self.load_chat(chat_id)?;

        let payloads = chat.send_message(content)?;

        // Ratchet state is automatically persisted by RatchetSession

        let remote_id = chat.remote_id();
        Ok(payloads
            .into_iter()
            .map(|p| p.to_envelope(remote_id.clone()))
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
        // Try to decode as an envelope
        if let Ok(envelope) = proto::EnvelopeV1::decode(payload) {
            let chat_id = &envelope.conversation_hint;

            // Check if we have this chat - if so, route to it for decryption
            if !chat_id.is_empty() && self.chat_exists(chat_id)? {
                return self.receive_message(chat_id, &envelope.payload);
            }

            // We don't have this chat - try to handle as inbox handshake
            // Pass the conversation_hint so both parties use the same chat ID
            return self.handle_inbox_handshake(chat_id, &envelope.payload);
        }

        // Not a valid envelope - generate a new chat ID (for backwards compatibility)
        let new_chat_id = crate::utils::generate_chat_id();
        self.handle_inbox_handshake(&new_chat_id, payload)
    }

    /// Handle an inbox handshake to establish a new chat.
    fn handle_inbox_handshake(
        &mut self,
        conversation_hint: &str,
        payload: &[u8],
    ) -> Result<ContentData, ChatManagerError> {
        let ratchet_storage = self.create_ratchet_storage()?;
        let result = self
            .inbox
            .handle_frame(ratchet_storage, conversation_hint, payload)?;

        let chat_id = result.convo.id().to_string();

        // Persist the new chat metadata
        let chat_record = ChatRecord {
            chat_id: chat_id.clone(),
            chat_type: "private_v1".to_string(),
            remote_public_key: Some(result.remote_public_key),
            remote_address: hex::encode(result.remote_public_key),
            created_at: crate::utils::timestamp_millis() as i64,
        };
        self.storage.save_chat(&chat_record)?;

        // Ratchet state is automatically persisted by RatchetSession
        // result.convo is dropped here - state already saved

        Ok(ContentData {
            conversation_id: chat_id,
            data: result.initial_content.unwrap_or_default(),
        })
    }

    /// Receive and decrypt a message for an existing chat.
    ///
    /// The payload should be the raw encrypted payload bytes.
    pub fn receive_message(
        &mut self,
        chat_id: &str,
        payload: &[u8],
    ) -> Result<ContentData, ChatManagerError> {
        // Load chat from storage
        let mut chat = self.load_chat(chat_id)?;

        // Decode and decrypt the payload
        let encrypted_payload = proto::EncryptedPayload::decode(payload).map_err(|e| {
            ChatManagerError::Chat(ChatError::Protocol(format!("failed to decode: {}", e)))
        })?;

        let frame = chat.decrypt(encrypted_payload)?;
        let content = PrivateV1Convo::extract_content(&frame).unwrap_or_default();

        // Ratchet state is automatically persisted by RatchetSession

        Ok(ContentData {
            conversation_id: chat_id.to_string(),
            data: content,
        })
    }

    /// List all chat IDs from storage.
    pub fn list_chats(&self) -> Result<Vec<String>, ChatManagerError> {
        Ok(self.storage.list_chat_ids()?)
    }

    /// Check if a chat exists in storage.
    pub fn chat_exists(&self, chat_id: &str) -> Result<bool, ChatManagerError> {
        Ok(self.storage.chat_exists(chat_id)?)
    }

    /// Delete a chat from storage.
    pub fn delete_chat(&mut self, chat_id: &str) -> Result<(), ChatManagerError> {
        self.storage.delete_chat(chat_id)?;
        // Also delete ratchet state from double-ratchets storage
        if let Ok(mut ratchet_storage) = self.create_ratchet_storage() {
            let _ = ratchet_storage.delete(chat_id);
        }
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
        let stored = alice.list_chats().unwrap();
        assert!(stored.contains(&chat_id));
    }

    #[test]
    fn test_inbox_key_persistence() {
        let mut manager = ChatManager::in_memory().unwrap();

        // Create intro bundle (should persist ephemeral key)
        let intro = manager.create_intro_bundle().unwrap();
        let key_hex = hex::encode(intro.ephemeral_key.as_bytes());

        // Key should be persisted
        let all_keys = manager.storage.load_all_inbox_keys().unwrap();
        assert!(all_keys.contains_key(&key_hex));
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
        assert!(alice.list_chats().unwrap().is_empty());
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

            // Chat should be in storage
            assert!(alice.chat_exists(&chat_id).unwrap());
        }
        // alice is dropped here, simulating app close

        // Scope 2: Reopen and verify chat is restored
        {
            let mut alice2 =
                ChatManager::open(StorageConfig::File(db_path.to_str().unwrap().to_string()))
                    .unwrap();

            // Chat should still be in storage
            assert!(alice2.list_chats().unwrap().contains(&chat_id));

            // Send another message - this will load the chat and advance ratchet
            let result = alice2.send_message(&chat_id, b"Message 4");
            assert!(result.is_ok(), "Should be able to send after restore");
        }
    }

    #[test]
    fn test_full_message_roundtrip() {
        use tempfile::tempdir;

        // Use temp files instead of in-memory for proper storage sharing
        let dir = tempdir().unwrap();
        let alice_db = dir.path().join("alice.db");
        let bob_db = dir.path().join("bob.db");

        let mut alice =
            ChatManager::open(StorageConfig::File(alice_db.to_str().unwrap().to_string())).unwrap();
        let mut bob =
            ChatManager::open(StorageConfig::File(bob_db.to_str().unwrap().to_string())).unwrap();

        // Bob creates an intro bundle and shares it with Alice
        let bob_intro = bob.create_intro_bundle().unwrap();

        // Alice starts a chat with Bob and sends "Hello!"
        let (alice_chat_id, envelopes) =
            alice.start_private_chat(&bob_intro, "Hello Bob!").unwrap();

        // Verify Alice has the chat
        assert!(alice.chat_exists(&alice_chat_id).unwrap());
        assert_eq!(alice.list_chats().unwrap().len(), 1);

        // Simulate network delivery: Bob receives the envelope
        let envelope = envelopes.first().unwrap();
        let content = bob.handle_incoming(&envelope.data).unwrap();

        // Bob should have received the message
        assert_eq!(content.data, b"Hello Bob!");

        // Bob should now have a chat
        assert_eq!(bob.list_chats().unwrap().len(), 1);
        let bob_chat_id = bob.list_chats().unwrap().first().unwrap().clone();

        // Bob replies to Alice
        let bob_reply_envelopes = bob.send_message(&bob_chat_id, b"Hi Alice!").unwrap();
        assert!(!bob_reply_envelopes.is_empty());

        // Alice receives Bob's reply
        let bob_reply = bob_reply_envelopes.first().unwrap();
        let alice_received = alice.handle_incoming(&bob_reply.data).unwrap();

        assert_eq!(alice_received.data, b"Hi Alice!");
        assert_eq!(alice_received.conversation_id, alice_chat_id);

        // Continue the conversation - Alice sends another message
        let alice_envelopes = alice.send_message(&alice_chat_id, b"How are you?").unwrap();
        let alice_msg = alice_envelopes.first().unwrap();
        let bob_received = bob.handle_incoming(&alice_msg.data).unwrap();

        assert_eq!(bob_received.data, b"How are you?");

        // Bob replies again
        let bob_envelopes = bob
            .send_message(&bob_chat_id, b"I'm good, thanks!")
            .unwrap();
        let bob_msg = bob_envelopes.first().unwrap();
        let alice_received2 = alice.handle_incoming(&bob_msg.data).unwrap();

        assert_eq!(alice_received2.data, b"I'm good, thanks!");
    }

    #[test]
    fn test_message_persistence_across_sessions() {
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let alice_db = dir.path().join("alice.db");
        let bob_db = dir.path().join("bob.db");

        let alice_chat_id;
        let bob_chat_id;
        let bob_intro;

        // Phase 1: Establish chat
        {
            let mut alice =
                ChatManager::open(StorageConfig::File(alice_db.to_str().unwrap().to_string()))
                    .unwrap();
            let mut bob =
                ChatManager::open(StorageConfig::File(bob_db.to_str().unwrap().to_string()))
                    .unwrap();

            bob_intro = bob.create_intro_bundle().unwrap();
            let (chat_id, envelopes) = alice.start_private_chat(&bob_intro, "Initial").unwrap();
            alice_chat_id = chat_id;

            // Bob receives
            let envelope = envelopes.first().unwrap();
            let content = bob.handle_incoming(&envelope.data).unwrap();
            assert_eq!(content.data, b"Initial");
            bob_chat_id = bob.list_chats().unwrap().first().unwrap().clone();
        }
        // Both dropped - simulates app restart

        // Phase 2: Continue conversation after restart
        {
            let mut alice =
                ChatManager::open(StorageConfig::File(alice_db.to_str().unwrap().to_string()))
                    .unwrap();
            let mut bob =
                ChatManager::open(StorageConfig::File(bob_db.to_str().unwrap().to_string()))
                    .unwrap();

            // Both should have persisted chats
            assert!(alice.list_chats().unwrap().contains(&alice_chat_id));
            assert!(bob.list_chats().unwrap().contains(&bob_chat_id));

            // Alice sends a message (chat loads from storage)
            let envelopes = alice
                .send_message(&alice_chat_id, b"After restart")
                .unwrap();

            // Bob receives (chat loads from storage)
            let envelope = envelopes.first().unwrap();
            let content = bob.handle_incoming(&envelope.data).unwrap();
            assert_eq!(content.data, b"After restart");

            // Bob replies
            let bob_envelopes = bob.send_message(&bob_chat_id, b"Still works!").unwrap();
            let bob_msg = bob_envelopes.first().unwrap();
            let alice_received = alice.handle_incoming(&bob_msg.data).unwrap();
            assert_eq!(alice_received.data, b"Still works!");
        }
    }
}
