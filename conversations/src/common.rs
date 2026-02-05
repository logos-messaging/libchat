use std::fmt::Debug;

use crate::dm::privatev1::PrivateV1Convo;
pub use crate::errors::ChatError;
use crate::types::AddressedEncryptedPayload;

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

pub trait Chat: HasChatId + Debug {
    fn send_message(&mut self, content: &[u8])
    -> Result<Vec<AddressedEncryptedPayload>, ChatError>;

    fn remote_id(&self) -> String;
}
