pub mod group_v1;
mod privatev1;

use crate::{
    DeliveryService, RegistrationService,
    ctx::ClientCtx,
    types::{AddressedEncryptedPayload, ContentData},
};
use chat_proto::logoschat::encryption::EncryptedPayload;
use std::fmt::Debug;
use std::sync::Arc;
use storage::{ChatStore, ConversationKind, ConversationStore, RatchetStore};

pub use crate::errors::ChatError;
pub use group_v1::{GroupV1Convo, IdentityProvider, LogosMlsProvider};
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

pub trait GroupConvo<DS: DeliveryService, RS: RegistrationService, CS: ChatStore>: Convo {
    fn add_member(
        &mut self,
        ctx: &mut ClientCtx<DS, RS, CS>,
        members: &[&str],
    ) -> Result<(), ChatError>;

    // Default implementation which dispatches envelopes to the DeliveryService
    fn send_content(
        &mut self,
        ctx: &mut ClientCtx<DS, RS, CS>,
        content: &[u8],
    ) -> Result<(), ChatError> {
        let payloads = self.send_message(content)?;
        for payload in payloads {
            ctx.ds()
                .publish(payload.into_envelope(self.id().into()))
                .map_err(|e| ChatError::Delivery(e.to_string()))?;
        }
        Ok(())
    }
}

pub enum Conversation<S: ConversationStore + RatchetStore> {
    Private(PrivateV1Convo<S>),
}
