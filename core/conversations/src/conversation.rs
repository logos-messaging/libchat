pub mod group_v1;
mod privatev1;

pub use crate::errors::ChatError;
use crate::outcomes::ConvoOutcome;
use crate::proto::EncryptedPayload;
use crate::service_context::{ExternalServices, ServiceContext};
use crate::types::AccountId;
pub use group_v1::GroupV1Convo;
use logos_traits::IdentIdRef;
pub use privatev1::PrivateV1Convo;
use std::fmt::Debug;

pub type ConversationId = String;

/// Behaviour shared by every conversation kind.
pub(crate) trait Convo<S: ExternalServices> {
    fn send_content(&mut self, cx: &mut ServiceContext<S>, content: &[u8])
    -> Result<(), ChatError>;

    /// Decrypts and processes an incoming encrypted frame.
    ///
    /// Returns the [`ConvoOutcome`] describing what the frame produced; its
    /// `content` is `None` for protocol-only frames (placeholders, MLS
    /// commits). Errors only on decryption or frame-parsing failure.
    fn handle_frame(
        &mut self,
        cx: &mut ServiceContext<S>,
        enc: EncryptedPayload,
    ) -> Result<ConvoOutcome, ChatError>;
}

/// Group-only operations.
pub(crate) trait GroupConvo<S: ExternalServices>: Convo<S> {
    fn add_member(
        &mut self,
        cx: &mut ServiceContext<S>,
        members: &[&AccountId],
    ) -> Result<(), ChatError>;
}
