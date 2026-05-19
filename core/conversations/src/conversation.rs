pub mod group_v1;
mod privatev1;

use crate::{
    DeliveryService,
    service_traits::KeyPackageProvider,
    types::{AccountId, AddressedEncryptedPayload, ContentData},
};
use chat_proto::logoschat::encryption::EncryptedPayload;
use std::fmt::Debug;
use std::sync::Arc;
use storage::{ConversationKind, ConversationStore, RatchetStore};

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
    /// Returns `Ok(Some(ContentData))` if the frame contains user content,
    /// `Ok(None)` for protocol frames (e.g., placeholders), or an error if
    /// decryption or frame parsing fails.
    fn handle_frame(
        &mut self,
        enc_payload: EncryptedPayload,
    ) -> Result<Option<ContentData>, ChatError>;

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

pub enum Conversation<S: ConversationStore + RatchetStore> {
    Private(PrivateV1Convo<S>),
}
