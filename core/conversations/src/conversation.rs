mod direct_v1;
pub mod group_v1;
mod group_v2;
pub mod mls_extensions;
mod privatev1;

pub use crate::errors::ChatError;
use crate::outcomes::ConvoOutcome;
use crate::proto::EncryptedPayload;
use crate::service_context::{ExternalServices, ServiceContext};
use crate::types::ConvoMetadata;
pub use direct_v1::DirectV1Convo;
pub use group_v1::GroupV1Convo;
pub use group_v2::{GroupV2Clock, GroupV2Convo};
pub use privatev1::PrivateV1Convo;
use shared_traits::IdentIdRef;

pub type ConversationId = String;
pub type ConversationIdRef<'a> = &'a str;

/// Behaviour shared by every conversation kind.
pub(crate) trait Convo<S: ExternalServices>: Identified + Send {
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

    /// Advances any time-driven protocol work (de-mls consensus deadlines) and
    /// reports what it observed, mirroring [`Self::handle_frame`].
    fn wakeup(&mut self, service_ctx: &mut ServiceContext<S>) -> Result<ConvoOutcome, ChatError>;
}

/// Group-only operations.
pub(crate) trait GroupConvo<S: ExternalServices>: Convo<S> + std::fmt::Debug + Send {
    fn add_member(
        &mut self,
        cx: &mut ServiceContext<S>,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError>;

    /// Each current member's MLS leaf-credential content (hex-encoded), self
    /// included.
    fn members(&self) -> Result<Vec<Vec<u8>>, ChatError>;
    // All GroupConvos MUST return ConvoMetadata
    // the return type is Option<_> to support legacy ConvoTypes which
    // are being phased out.
    fn metadata(&self) -> Option<ConvoMetadata>;
}

pub(crate) trait Identified {
    fn id(&self) -> ConversationIdRef<'_>;
}
