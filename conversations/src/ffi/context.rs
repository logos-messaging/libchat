//! FFI-oriented context that wraps ChatManager with handle-based access.
//!
//! For pure Rust usage, prefer using `ChatManager` directly.

use std::collections::HashMap;

use crate::{
    chat::{ChatManager, ChatManagerError, StorageConfig},
    errors::ChatError,
    types::{AddressedEnvelope, ContentData},
};

pub use crate::inbox::Introduction;

// Offset handles to make debugging easier
const INITIAL_CONVO_HANDLE: u32 = 0xF5000001;

/// Used to identify a conversation across the FFI boundary.
/// This is an opaque integer handle that maps to an internal ChatId string.
pub type ConvoHandle = u32;

/// Context is the FFI-oriented wrapper around ChatManager.
///
/// It provides handle-based access to chats, suitable for FFI consumers
/// that can't work with Rust strings directly.
///
/// For pure Rust usage, prefer using `ChatManager` directly.
pub struct Context {
    manager: ChatManager,
    /// Maps FFI handles to internal chat IDs
    handle_to_chat_id: HashMap<ConvoHandle, String>,
    /// Maps chat IDs back to FFI handles for lookup
    chat_id_to_handle: HashMap<String, ConvoHandle>,
    next_handle: ConvoHandle,
}

impl Context {
    pub fn new() -> Self {
        let manager = ChatManager::open(StorageConfig::InMemory)
            .expect("Failed to create in-memory ChatManager");
        Self {
            manager,
            handle_to_chat_id: HashMap::new(),
            chat_id_to_handle: HashMap::new(),
            next_handle: INITIAL_CONVO_HANDLE,
        }
    }

    /// Create a Context wrapping an existing ChatManager.
    pub fn with_manager(manager: ChatManager) -> Self {
        Self {
            manager,
            handle_to_chat_id: HashMap::new(),
            chat_id_to_handle: HashMap::new(),
            next_handle: INITIAL_CONVO_HANDLE,
        }
    }

    /// Access the underlying ChatManager for direct Rust API usage.
    pub fn manager(&self) -> &ChatManager {
        &self.manager
    }

    /// Access the underlying ChatManager mutably.
    pub fn manager_mut(&mut self) -> &mut ChatManager {
        &mut self.manager
    }

    /// Create an introduction bundle for sharing with other users.
    pub fn create_intro_bundle(&mut self) -> Result<Vec<u8>, ChatManagerError> {
        let intro = self.manager.create_intro_bundle()?;
        Ok(intro.into())
    }

    /// Create a new private conversation using a remote party's introduction bundle.
    ///
    /// Returns an FFI handle and addressed envelopes to be delivered.
    pub fn create_private_convo(
        &mut self,
        remote_bundle: &Introduction,
        content: String,
    ) -> (ConvoHandle, Vec<AddressedEnvelope>) {
        let (chat_id, envelopes) = self
            .manager
            .start_private_chat(remote_bundle, &content)
            .unwrap_or_else(|_| todo!("Log/Surface Error"));

        let handle = self.register_chat_id(chat_id);
        (handle, envelopes)
    }

    /// Send content to an existing conversation identified by handle.
    pub fn send_content(
        &mut self,
        convo_handle: ConvoHandle,
        content: &[u8],
    ) -> Result<Vec<AddressedEnvelope>, ChatManagerError> {
        let chat_id = self.resolve_handle(convo_handle)?;
        self.manager.send_message(&chat_id, content)
    }

    /// Handle an incoming payload.
    pub fn handle_payload(&mut self, payload: &[u8]) -> Option<ContentData> {
        self.manager.handle_incoming(payload).ok()
    }

    /// Get the chat ID for a given handle.
    pub fn get_chat_id(&self, handle: ConvoHandle) -> Option<&str> {
        self.handle_to_chat_id.get(&handle).map(|s| s.as_str())
    }

    /// Get the handle for a given chat ID.
    pub fn get_handle(&self, chat_id: &str) -> Option<ConvoHandle> {
        self.chat_id_to_handle.get(chat_id).copied()
    }

    // --- Internal helpers ---

    /// Register a chat ID and return its FFI handle.
    fn register_chat_id(&mut self, chat_id: String) -> ConvoHandle {
        // Check if already registered
        if let Some(&handle) = self.chat_id_to_handle.get(&chat_id) {
            return handle;
        }

        let handle = self.next_handle;
        self.next_handle += 1;

        self.handle_to_chat_id.insert(handle, chat_id.clone());
        self.chat_id_to_handle.insert(chat_id, handle);

        handle
    }

    /// Resolve a handle to its chat ID.
    fn resolve_handle(&self, handle: ConvoHandle) -> Result<String, ChatManagerError> {
        self.handle_to_chat_id
            .get(&handle)
            .cloned()
            .ok_or_else(|| ChatError::NoConvo(handle).into())
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}
