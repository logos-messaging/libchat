use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

pub use crate::errors::ChatError;
use crate::types::{AddressedEncryptedPayload, ContentData};

pub type SessionId<'a> = &'a str;
pub type SessionIdOwned = Arc<str>;

pub trait HasConversationId: Debug {
    fn id(&self) -> SessionId<'_>;
}

#[allow(dead_code)]
pub trait InboundSessionHandler: HasConversationId + Debug {
    fn handle_frame(
        &mut self,
        encoded_payload: &[u8],
    ) -> Result<(Box<dyn OutboundSession>, Vec<ContentData>), ChatError>;
}

pub trait OutboundSession: HasConversationId + Debug {
    fn send_message(&mut self, content: &[u8])
    -> Result<Vec<AddressedEncryptedPayload>, ChatError>;

    fn remote_id(&self) -> String;
}

#[allow(dead_code)]
pub struct SessionRegistry {
    sessions: HashMap<Arc<str>, Box<dyn OutboundSession>>,
    handlers: HashMap<Arc<str>, Box<dyn InboundSessionHandler>>,
}

#[allow(dead_code)]
impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            handlers: HashMap::new(),
        }
    }

    pub fn insert_session(
        &mut self,
        conversation: impl OutboundSession + HasConversationId + 'static,
    ) -> SessionIdOwned {
        let key: SessionIdOwned = Arc::from(conversation.id());
        self.sessions.insert(key.clone(), Box::new(conversation));
        key
    }

    pub fn register_handler(
        &mut self,
        handler: impl InboundSessionHandler + HasConversationId + 'static,
    ) -> SessionIdOwned {
        let key: SessionIdOwned = Arc::from(handler.id());
        self.handlers.insert(key.clone(), Box::new(handler));
        key
    }

    pub fn get_session(&self, id: SessionId) -> Option<&(dyn OutboundSession + '_)> {
        self.sessions.get(id).map(|c| c.as_ref())
    }

    pub fn get_mut_session(&mut self, id: &str) -> Option<&mut (dyn OutboundSession + '_)> {
        Some(self.sessions.get_mut(id)?.as_mut())
    }

    pub fn get_handler(&mut self, id: SessionId) -> Option<&mut (dyn InboundSessionHandler + '_)> {
        Some(self.handlers.get_mut(id)?.as_mut())
    }

    pub fn session_ids(&self) -> impl Iterator<Item = SessionIdOwned> + '_ {
        self.sessions.keys().cloned()
    }

    pub fn handler_ids(&self) -> impl Iterator<Item = SessionIdOwned> + '_ {
        self.handlers.keys().cloned()
    }
}
