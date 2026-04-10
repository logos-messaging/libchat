mod privatev1;

use crate::types::{AddressedEncryptedPayload, ContentData};
use chat_proto::logoschat::encryption::EncryptedPayload;
use std::fmt::Debug;
use std::sync::Arc;
use storage::{ConversationKind, ConversationStore, RatchetStore};

pub use crate::errors::ChatError;
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

pub enum Conversation<S: ConversationStore + RatchetStore> {
    Private(PrivateV1Convo<S>),
}
