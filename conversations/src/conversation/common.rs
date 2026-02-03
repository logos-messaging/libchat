use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

pub use crate::errors::ChatError;
use crate::types::{AddressedEncryptedPayload, ContentData};

pub type ConversationId<'a> = &'a str;
pub type ConversationIdOwned = Arc<str>;

pub trait HasConversationId: Debug {
    fn id(&self) -> ConversationId;
}

pub trait ConvoFactory: HasConversationId + Debug {
    fn handle_frame(
        &mut self,
        encoded_payload: &[u8],
    ) -> Result<(Box<dyn Convo>, Vec<ContentData>), ChatError>;
}

pub trait Convo: HasConversationId + Debug {
    fn send_message(&mut self, content: &[u8])
    -> Result<Vec<AddressedEncryptedPayload>, ChatError>;

    fn remote_id(&self) -> String;
}

pub struct ConversationStore {
    conversations: HashMap<Arc<str>, Box<dyn Convo>>,
    factories: HashMap<Arc<str>, Box<dyn ConvoFactory>>,
}

impl ConversationStore {
    pub fn new() -> Self {
        Self {
            conversations: HashMap::new(),
            factories: HashMap::new(),
        }
    }

    pub fn insert_convo(
        &mut self,
        conversation: impl Convo + HasConversationId + 'static,
    ) -> ConversationIdOwned {
        let key: ConversationIdOwned = Arc::from(conversation.id());
        self.conversations
            .insert(key.clone(), Box::new(conversation));
        key
    }

    pub fn register_factory(
        &mut self,
        handler: impl ConvoFactory + HasConversationId + 'static,
    ) -> ConversationIdOwned {
        let key: ConversationIdOwned = Arc::from(handler.id());
        self.factories.insert(key.clone(), Box::new(handler));
        key
    }

    pub fn get(&self, id: ConversationId) -> Option<&(dyn Convo + '_)> {
        self.conversations.get(id).map(|c| c.as_ref())
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut (dyn Convo + '_)> {
        Some(self.conversations.get_mut(id)?.as_mut())
    }

    pub fn get_factory(&mut self, id: ConversationId) -> Option<&mut (dyn ConvoFactory + '_)> {
        Some(self.factories.get_mut(id)?.as_mut())
    }

    pub fn conversation_ids(&self) -> impl Iterator<Item = ConversationIdOwned> + '_ {
        self.conversations.keys().cloned()
    }

    pub fn factory_ids(&self) -> impl Iterator<Item = ConversationIdOwned> + '_ {
        self.factories.keys().cloned()
    }
}
