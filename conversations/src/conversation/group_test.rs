use crate::{
    conversation::{ChatError, ConversationId, Convo, Id},
    types::AddressedEncryptedPayload,
};

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
    fn send_message(
        &mut self,
        _content: &[u8],
    ) -> Result<Vec<AddressedEncryptedPayload>, ChatError> {
        Ok(vec![])
    }

    fn remote_id(&self) -> String {
        self.id().to_string()
    }
}
