use crate::conversation::{ChatError, ConversationId, Convo};

#[derive(Debug)]
pub struct Inbox {
    address: String,
}

impl Inbox {
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
        }
    }
}

impl Convo for Inbox {
    fn id(&self) -> ConversationId {
        self.address.as_ref()
    }

    fn send_frame(&mut self, _message: &[u8]) -> Result<(), ChatError> {
        todo!("Not Implemented")
    }

    fn handle_frame(&mut self, message: &[u8]) -> Result<(), ChatError> {
        if message.len() == 0 {
            return Err(ChatError::Protocol("Example error".into()));
        }
        todo!("Not Implemented")
    }
}
