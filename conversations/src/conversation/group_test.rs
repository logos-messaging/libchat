use crate::conversation::{ChatError, ConversationId, Convo};

#[derive(Debug)]
pub struct GroupTestConvo {}

impl GroupTestConvo {
    pub fn new() -> Self {
        Self {}
    }
}

impl Convo for GroupTestConvo {
    fn id(&self) -> ConversationId {
        // implementation
        "grouptest"
    }

    fn send_frame(&mut self, _message: &[u8]) -> Result<(), ChatError> {
        // todo!("Not Implemented")
        Ok(())
    }

    fn handle_frame(&mut self, _message: &[u8]) -> Result<(), ChatError> {
        // todo!("Not Implemented")
        Ok(())
    }
}
