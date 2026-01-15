use chat_proto::logoschat::encryption::EncryptedPayload;

use crate::conversation::{ChatError, ConversationId, Convo, Id, PayloadHandler};

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
    fn send_frame(&mut self, _message: &[u8]) -> Result<(), ChatError> {
        // todo!("Not Implemented")
        Ok(())
    }

    fn send_message(&mut self, _content: &[u8]) -> Result<Vec<EncryptedPayload>, ChatError> {
        Ok(vec![])
    }
}

impl PayloadHandler for GroupTestConvo {
    fn handle_frame(&mut self, _message: &[u8]) -> Result<(), ChatError> {
        Ok(())
    }
}
