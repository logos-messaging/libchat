use crate::conversation::{ChatError, ConversationId, Convo};

#[derive(Debug)]
pub struct PrivateV1Convo {}

impl PrivateV1Convo {
    pub fn new() -> Self {
        Self {}
    }
}

impl Convo for PrivateV1Convo {
    fn id(&self) -> ConversationId {
        // implementation
        "private_v1_convo_id"
    }

    fn send_frame(&mut self, _message: &[u8]) -> Result<(), ChatError> {
        todo!("Not Implemented")
    }

    fn handle_frame(&mut self, _message: &[u8]) -> Result<(), ChatError> {
        todo!("Not Implemented")
    }
}
