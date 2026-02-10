use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

pub use crate::errors::ChatError;
use crate::types::{AddressedEncryptedPayload, ContentData};

pub type ConversationId<'a> = &'a str;
pub type ConversationIdOwned = Arc<str>;

pub trait Id: Debug {
    fn id(&self) -> ConversationId;
}

pub trait Convo: Id + Debug {
    fn send_message(&mut self, content: &[u8])
    -> Result<Vec<AddressedEncryptedPayload>, ChatError>;

    /// Decrypts and processes an incoming encrypted frame.
    ///
    /// Returns `Ok(Some(ContentData))` if the frame contains user content,
    /// `Ok(None)` for protocol frames (e.g., placeholders), or an error if
    /// decryption or frame parsing fails.
    fn handle_frame(
        &mut self,
        enc_payload: EncryptedPayload,
    ) -> Result<Option<ContentData>, ChatError>;

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

    pub fn insert_convo(&mut self, conversation: Box<dyn Convo>) -> ConversationIdOwned {
        let key: ConversationIdOwned = Arc::from(conversation.id());
        self.conversations.insert(key.clone(), conversation);
        key
    }

    pub fn has(&self, id: ConversationId) -> bool {
        self.conversations.contains_key(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut (dyn Convo + '_)> {
        Some(self.conversations.get_mut(id)?.as_mut())
    }

    #[allow(dead_code)]
    pub fn conversation_ids(&self) -> Vec<ConversationIdOwned> {
        self.conversations.keys().cloned().collect()
    }
}

#[cfg(test)]
mod group_test;
mod privatev1;

use chat_proto::logoschat::encryption::EncryptedPayload;
#[cfg(test)]
pub(crate) use group_test::GroupTestConvo;
pub use privatev1::PrivateV1Convo;
