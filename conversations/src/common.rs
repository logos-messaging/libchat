use std::fmt::Debug;

use crate::dm::privatev1::PrivateV1Convo;
pub use crate::errors::ChatError;
use crate::types::AddressedEncryptedPayload;
use double_ratchets::storage::RatchetStorage;

pub type ChatId<'a> = &'a str;

pub trait HasChatId: Debug {
    fn id(&self) -> ChatId<'_>;
}

/// Result of handling an incoming inbox message (new chat invitation).
pub struct InboxHandleResult {
    /// The newly created conversation.
    pub convo: PrivateV1Convo,
    /// The remote party's public key (for storage/display).
    pub remote_public_key: [u8; 32],
    /// Decrypted initial message content, if any.
    pub initial_content: Option<Vec<u8>>,
}

pub trait InboundMessageHandler {
    /// Handle an incoming inbox frame.
    ///
    /// `conversation_hint` is the sender's conversation ID from the envelope,
    /// which should be used as the shared conversation ID for this chat.
    fn handle_frame(
        &mut self,
        storage: RatchetStorage,
        conversation_hint: &str,
        encoded_payload: &[u8],
    ) -> Result<InboxHandleResult, ChatError>;
}

pub trait Chat: HasChatId + Debug {
    fn send_message(&mut self, content: &[u8])
    -> Result<Vec<AddressedEncryptedPayload>, ChatError>;

    fn remote_id(&self) -> String;
}
