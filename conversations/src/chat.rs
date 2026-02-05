use std::rc::Rc;

use crate::{
    common::{Chat, ChatStore, HasChatId},
    errors::ChatError,
    identity::Identity,
    inbox::{Inbox, Introduction},
    types::{AddressedEnvelope, ContentData},
};

/// ChatManager is the main entry point for the conversations API.
/// It manages identity, inbox, and active chats.
///
/// This is a pure Rust API - for FFI bindings, use `Context` which wraps this
/// with handle-based access.
pub struct ChatManager {
    identity: Rc<Identity>,
    store: ChatStore,
    inbox: Inbox,
}

impl ChatManager {
    /// Create a new ChatManager with a fresh identity.
    pub fn new() -> Self {
        let identity = Rc::new(Identity::new());
        let inbox = Inbox::new(Rc::clone(&identity));
        Self {
            identity,
            store: ChatStore::new(),
            inbox,
        }
    }

    /// Create a new ChatManager with an existing identity.
    pub fn with_identity(identity: Identity) -> Self {
        let identity = Rc::new(identity);
        let inbox = Inbox::new(Rc::clone(&identity));
        Self {
            identity,
            store: ChatStore::new(),
            inbox,
        }
    }

    /// Get the local identity's public address.
    pub fn local_address(&self) -> String {
        self.identity.address()
    }

    /// Create an introduction bundle that can be shared with others.
    /// They can use this to initiate a chat with you.
    pub fn create_intro_bundle(&mut self) -> Result<Introduction, ChatError> {
        let pkb = self.inbox.create_bundle();
        Ok(Introduction::from(pkb))
    }

    /// Start a new private conversation with someone using their introduction bundle.
    ///
    /// Returns the chat ID and envelopes that must be delivered to the remote party.
    pub fn start_private_chat(
        &mut self,
        remote_bundle: &Introduction,
        initial_message: &str,
    ) -> Result<(String, Vec<AddressedEnvelope>), ChatError> {
        let (convo, payloads) = self
            .inbox
            .invite_to_private_convo(remote_bundle, initial_message.to_string())?;

        let chat_id = convo.id().to_string();

        let envelopes: Vec<AddressedEnvelope> = payloads
            .into_iter()
            .map(|p| p.to_envelope(chat_id.clone()))
            .collect();

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
    ) -> Result<Vec<AddressedEnvelope>, ChatError> {
        let chat = self
            .store
            .get_mut_chat(chat_id)
            .ok_or_else(|| ChatError::NoChatId(chat_id.to_string()))?;

        let payloads = chat.send_message(content)?;

        Ok(payloads
            .into_iter()
            .map(|p| p.to_envelope(chat.remote_id()))
            .collect())
    }

    /// Handle an incoming payload from the network.
    ///
    /// Returns the decrypted content if successful.
    pub fn handle_incoming(&mut self, _payload: &[u8]) -> Result<ContentData, ChatError> {
        // TODO: Implement proper payload handling
        // 1. Determine if this is an inbox message or a chat message
        // 2. Route to appropriate handler
        // 3. Return decrypted content
        Ok(ContentData {
            conversation_id: "convo_id".into(),
            data: vec![1, 2, 3, 4, 5, 6],
        })
    }

    /// Get a reference to an active chat.
    pub fn get_chat(&self, chat_id: &str) -> Option<&dyn Chat> {
        self.store.get_chat(chat_id)
    }

    /// Get a mutable reference to an active chat.
    pub fn get_chat_mut(&mut self, chat_id: &str) -> Option<&mut dyn Chat> {
        self.store.get_mut_chat(chat_id)
    }

    /// List all active chat IDs.
    pub fn list_chats(&self) -> Vec<String> {
        self.store.chat_ids().map(|id| id.to_string()).collect()
    }
}

impl Default for ChatManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_chat_manager() {
        let manager = ChatManager::new();
        assert!(!manager.local_address().is_empty());
    }

    #[test]
    fn test_create_intro_bundle() {
        let mut manager = ChatManager::new();
        let bundle = manager.create_intro_bundle();
        assert!(bundle.is_ok());
    }

    #[test]
    fn test_start_private_chat() {
        let mut alice = ChatManager::new();
        let mut bob = ChatManager::new();

        // Bob creates an intro bundle
        let bob_intro = bob.create_intro_bundle().unwrap();

        // Alice starts a chat with Bob
        let result = alice.start_private_chat(&bob_intro, "Hello Bob!");
        assert!(result.is_ok());

        let (chat_id, envelopes) = result.unwrap();
        assert!(!chat_id.is_empty());
        assert!(!envelopes.is_empty());
    }
}
