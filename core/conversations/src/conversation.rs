pub mod group_v1;
mod privatev1;

use crate::{
    DeliveryService,
    outcomes::ConvoOutcome,
    service_traits::KeyPackageProvider,
    types::{AccountId, AddressedEncryptedPayload},
};
use chat_proto::logoschat::encryption::EncryptedPayload;
use std::fmt::Debug;
use storage::ConversationKind;

pub use crate::errors::ChatError;
pub use group_v1::{GroupV1Convo, IdentityProvider};
pub use privatev1::PrivateV1Convo;

pub type ConversationId = String;

pub trait Id: Debug {
    fn id(&self) -> &str;
}

pub trait Convo: Id + Debug {
    fn send_message(&mut self, content: &[u8])
    -> Result<Vec<AddressedEncryptedPayload>, ChatError>;

    /// Decrypts and processes an incoming encrypted frame.
    ///
    /// Returns the [`ConvoOutcome`] describing what the frame produced; its
    /// `content` is `None` for protocol-only frames (placeholders, MLS
    /// commits). Errors only on decryption or frame-parsing failure.
    fn handle_frame(&mut self, enc_payload: EncryptedPayload) -> Result<ConvoOutcome, ChatError>;

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
