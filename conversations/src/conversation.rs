use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

pub use crate::errors::ChatError;
use crate::types::ContentData;

pub type ConversationId<'a> = &'a str;
pub type ConversationIdOwned = Arc<str>;

pub trait Id: Debug {
    fn id(&self) -> ConversationId;
}

pub trait ConvoFactory: Id + Debug {
    fn handle_frame(
        &mut self,
        encoded_payload: &[u8],
    ) -> Result<(Box<dyn Convo>, Vec<ContentData>), ChatError>;
}

pub trait Convo: Id + Debug {
    fn send_message(&mut self, content: &[u8]) -> Result<Vec<EncryptedPayload>, ChatError>;
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

    pub fn insert_convo(&mut self, conversation: impl Convo + Id + 'static) -> ConversationIdOwned {
        let key: ConversationIdOwned = Arc::from(conversation.id());
        self.conversations
            .insert(key.clone(), Box::new(conversation));
        key
    }

    pub fn register_factory(
        &mut self,
        handler: impl ConvoFactory + Id + 'static,
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

mod group_test;
mod privatev1;

use crate::proto::EncryptedPayload;
pub use group_test::GroupTestConvo;
pub use privatev1::PrivateV1Convo;
