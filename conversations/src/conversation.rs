use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

pub use crate::errors::ChatError;

/////////////////////////////////////////////////
// Type Definitions
/////////////////////////////////////////////////

pub type ConversationId<'a> = &'a str;
pub type ConversationIdOwned = Arc<str>;

/////////////////////////////////////////////////
// Trait Definitions
/////////////////////////////////////////////////
pub trait Id: Debug {
    fn id(&self) -> ConversationId;
}

pub trait PayloadHandler: Id + Debug {
    fn handle_frame(&mut self, message: &[u8]) -> Result<(), ChatError>;
}

pub trait Convo: PayloadHandler + Id + Debug {
    fn send_message(&mut self, content: &[u8]) -> Result<Vec<EncryptedPayload>, ChatError>;
    fn send_frame(&mut self, message: &[u8]) -> Result<(), ChatError>;
}

/////////////////////////////////////////////////
// Structs
/////////////////////////////////////////////////

pub struct ConversationStore {
    conversations: HashMap<Arc<str>, Box<dyn Convo>>,
    inbound_handlers: HashMap<Arc<str>, Box<dyn PayloadHandler>>,
}

impl ConversationStore {
    pub fn new() -> Self {
        Self {
            conversations: HashMap::new(),
            inbound_handlers: HashMap::new(),
        }
    }

    pub fn insert(&mut self, conversation: impl Convo + Id + 'static) -> ConversationIdOwned {
        let key: ConversationIdOwned = Arc::from(conversation.id());
        self.conversations
            .insert(key.clone(), Box::new(conversation));
        key
    }

    pub fn insert_handler(
        &mut self,
        handler: impl PayloadHandler + Id + 'static,
    ) -> ConversationIdOwned {
        let key: ConversationIdOwned = Arc::from(handler.id());
        self.inbound_handlers.insert(key.clone(), Box::new(handler));
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

/////////////////////////////////////////////////
// Modules
/////////////////////////////////////////////////

mod group_test;
mod privatev1;

use crate::proto::EncryptedPayload;
pub use group_test::GroupTestConvo;
pub use privatev1::PrivateV1Convo;
