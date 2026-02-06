use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

pub use crate::errors::ChatError;
use crate::types::AddressedEncryptedPayload;

pub type ConversationId<'a> = &'a str;
pub type ConversationIdOwned = Arc<str>;

pub trait Id: Debug {
    fn id(&self) -> ConversationId;
}

pub trait Convo: Id + Debug {
    fn send_message(&mut self, content: &[u8])
    -> Result<Vec<AddressedEncryptedPayload>, ChatError>;

    fn remote_id(&self) -> String;
}

pub struct ConversationStore {
    conversations: HashMap<Arc<str>, Box<dyn Convo>>,
}

impl ConversationStore {
    pub fn new() -> Self {
        Self {
            conversations: HashMap::new(),
        }
    }

    pub fn insert_convo(&mut self, conversation: impl Convo + Id + 'static) -> ConversationIdOwned {
        let key: ConversationIdOwned = Arc::from(conversation.id());
        self.conversations
            .insert(key.clone(), Box::new(conversation));
        key
    }

    pub fn get(&self, id: ConversationId) -> Option<&(dyn Convo + '_)> {
        self.conversations.get(id).map(|c| c.as_ref())
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut (dyn Convo + '_)> {
        Some(self.conversations.get_mut(id)?.as_mut())
    }

    pub fn conversation_ids(&self) -> impl Iterator<Item = ConversationIdOwned> + '_ {
        self.conversations.keys().cloned()
    }
}

mod group_test;
mod privatev1;

pub use group_test::GroupTestConvo;
pub use privatev1::PrivateV1Convo;
