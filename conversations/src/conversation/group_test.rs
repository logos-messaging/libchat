use chat_proto::logoschat::encryption::EncryptedPayload;

use crate::conversation::{ChatError, ConversationId, Convo, Id};

#[derive(Debug)]
pub struct GroupTestConvo {}

impl GroupTestConvo {
    pub fn new() -> Self {
        Self {}
    }
}

impl Id for GroupTestConvo {
    fn id(&self) -> ConversationId {
        // implementation
        "grouptest"
    }
}

impl Convo for GroupTestConvo {
    fn send_message(&mut self, _content: &[u8]) -> Result<Vec<EncryptedPayload>, ChatError> {
        Ok(vec![])
    }
}
