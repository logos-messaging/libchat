use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

pub use crate::errors::ChatError;
use crate::types::{AddressedEncryptedPayload, ContentData};

pub type ChatId<'a> = &'a str;
pub type ChatIdOwned = Arc<str>;

pub trait HasChatId: Debug {
    fn id(&self) -> ChatId<'_>;
}

pub trait InboundMessageHandler {
    fn handle_frame(
        &mut self,
        encoded_payload: &[u8],
    ) -> Result<(Box<dyn Chat>, Vec<ContentData>), ChatError>;
}

pub trait Chat: HasChatId + Debug {
    fn send_message(&mut self, content: &[u8])
    -> Result<Vec<AddressedEncryptedPayload>, ChatError>;

    fn remote_id(&self) -> String;
}

pub struct ChatStore {
    chats: HashMap<Arc<str>, Box<dyn Chat>>,
    handlers: HashMap<Arc<str>, Box<dyn InboundMessageHandler>>,
}

impl ChatStore {
    pub fn new() -> Self {
        Self {
            chats: HashMap::new(),
            handlers: HashMap::new(),
        }
    }

    pub fn insert_chat(&mut self, conversation: impl Chat + HasChatId + 'static) -> ChatIdOwned {
        let key: ChatIdOwned = Arc::from(conversation.id());
        self.chats.insert(key.clone(), Box::new(conversation));
        key
    }

    pub fn register_handler(
        &mut self,
        handler: impl InboundMessageHandler + HasChatId + 'static,
    ) -> ChatIdOwned {
        let key: ChatIdOwned = Arc::from(handler.id());
        self.handlers.insert(key.clone(), Box::new(handler));
        key
    }

    pub fn get_chat(&self, id: ChatId) -> Option<&(dyn Chat + '_)> {
        self.chats.get(id).map(|c| c.as_ref())
    }

    pub fn get_mut_chat(&mut self, id: &str) -> Option<&mut (dyn Chat + '_)> {
        Some(self.chats.get_mut(id)?.as_mut())
    }

    pub fn get_handler(&mut self, id: ChatId) -> Option<&mut (dyn InboundMessageHandler + '_)> {
        Some(self.handlers.get_mut(id)?.as_mut())
    }

    pub fn chat_ids(&self) -> impl Iterator<Item = ChatIdOwned> + '_ {
        self.chats.keys().cloned()
    }

    pub fn handler_ids(&self) -> impl Iterator<Item = ChatIdOwned> + '_ {
        self.handlers.keys().cloned()
    }
}
