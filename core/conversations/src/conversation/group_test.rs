use crate::{
    conversation::{ChatError, ConversationId, Convo, Id},
    proto::EncryptedPayload,
    types::{AddressedEncryptedPayload, ContentData},
};

#[derive(Debug)]
pub struct GroupTestConvo {}

impl GroupTestConvo {
    pub fn new() -> Self {
        Self {}
    }
}

impl Id for GroupTestConvo {
    fn id(&self) -> ConversationId<'_> {
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

    fn handle_frame(
        &mut self,
        _encoded_payload: EncryptedPayload,
    ) -> Result<Option<ContentData>, ChatError> {
        Ok(None)
    }

    fn remote_id(&self) -> String {
        self.id().to_string()
    }
}
