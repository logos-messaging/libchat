use std::fmt::Debug;

pub use crate::errors::ChatError;
use crate::types::{AddressedEncryptedPayload, ContentData};
use double_ratchets::storage::RatchetStorage;

pub type ChatId<'a> = &'a str;

pub trait HasChatId: Debug {
    fn id(&self) -> ChatId<'_>;
}

pub trait InboundMessageHandler {
    fn handle_frame(
        &mut self,
        storage: RatchetStorage,
        encoded_payload: &[u8],
    ) -> Result<(Box<dyn Chat>, Vec<ContentData>), ChatError>;
}

pub trait Chat: HasChatId + Debug {
    fn send_message(&mut self, content: &[u8])
    -> Result<Vec<AddressedEncryptedPayload>, ChatError>;

    fn remote_id(&self) -> String;
}
