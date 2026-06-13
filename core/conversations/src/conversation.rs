pub mod group_v1;
mod privatev1;

pub use crate::errors::ChatError;
use crate::outcomes::ConvoOutcome;
use crate::proto::EncryptedPayload;
use crate::service_context::{ExternalServices, ServiceContext};
pub use group_v1::GroupV1Convo;
pub use privatev1::PrivateV1Convo;
use shared_traits::IdentIdRef;

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

    fn wakeup(&mut self, service_ctx: &mut ServiceContext<S>) -> Result<(), ChatError>;
}

/// Group-only operations.
pub(crate) trait GroupConvo<S: ExternalServices>: Convo<S> {
    fn add_member(
        &mut self,
        cx: &mut ServiceContext<S>,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError>;
}
