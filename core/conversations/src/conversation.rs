pub mod group_v1;
mod privatev1;

use crate::{
    DeliveryService,
    response::FrameOutcome,
    service_traits::KeyPackageProvider,
    types::{AccountId, AddressedEncryptedPayload},
};
use chat_proto::logoschat::encryption::EncryptedPayload;
use std::fmt::Debug;
use std::sync::Arc;
use storage::ConversationKind;

pub use crate::errors::ChatError;
pub use group_v1::{GroupV1Convo, IdentityProvider};
pub use privatev1::PrivateV1Convo;

pub type ConversationId<'a> = &'a str;
pub type ConversationIdOwned = Arc<str>;

pub trait Id: Debug {
    fn id(&self) -> ConversationId<'_>;
}

pub trait Convo: Id + Debug {
    fn send_message(&mut self, content: &[u8])
    -> Result<Vec<AddressedEncryptedPayload>, ChatError>;

    /// Decrypts and processes an incoming encrypted frame.
    ///
    /// Returns the [`FrameOutcome`] describing what the frame produced. May be
    /// empty for protocol-only frames (placeholders, commits). Errors only on
    /// decryption or frame-parsing failure.
    fn handle_frame(&mut self, enc_payload: EncryptedPayload) -> Result<FrameOutcome, ChatError>;

    fn remote_id(&self) -> String;

    /// Returns the conversation type identifier for storage.
    fn convo_type(&self) -> ConversationKind;
}

pub trait GroupConvo<DS: DeliveryService, RS: KeyPackageProvider>: Convo {
    fn add_member(&mut self, members: &[&AccountId]) -> Result<(), ChatError>;

    // This is intended to replace `send_message`. The trait change is that it automatically
    // sends the payload directly.
    fn send_content(&mut self, content: &[u8]) -> Result<(), ChatError>;
}
