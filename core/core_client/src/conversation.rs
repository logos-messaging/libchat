mod group_v1;
mod group_v2;

use crate::{AccountId, ContentData, DeliveryService, RegistrationService};
use chat_proto::logoschat::encryption::EncryptedPayload;
use libchat::IdentityProvider;

use std::fmt::Debug;

pub use crate::ChatError;
pub use group_v1::GroupV1Convo;

pub type ConversationIdRef<'a> = &'a str;
pub type ConversationId = String;

/// A trait which bundles all the external service traits into a single scope.
/// This allows for a single bound to be used internally, and cuts down on
/// the clutter
pub trait ExternalServices: Debug {
    type IP: IdentityProvider;
    type DS: DeliveryService;
    type RS: RegistrationService;
}

#[derive(Debug)]
pub struct ServiceContext<S: ExternalServices> {
    pub(crate) identity_provider: S::IP,
    pub(crate) ds: S::DS,
    pub(crate) rs: S::RS,
}

impl<S: ExternalServices> ServiceContext<S> {
    pub fn new(identity_provider: S::IP, ds: S::DS, rs: S::RS) -> Self {
        ServiceContext {
            identity_provider,
            ds,
            rs,
        }
    }
}

pub trait Id: Debug {
    fn id(&self) -> ConversationIdRef<'_>;
}

pub trait BaseConvo<S: ExternalServices>: Id + Debug {
    fn init(&self, service_ctx: &mut ServiceContext<S>) -> Result<(), ChatError>;

    fn send_content(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        content: &[u8],
    ) -> Result<(), ChatError>;

    fn handle_frame(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        enc_payload: EncryptedPayload,
    ) -> Result<Option<ContentData>, ChatError>;
}

pub trait BaseGroupConvo<S: ExternalServices>: BaseConvo<S> {
    fn add_member(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        members: &[&AccountId],
    ) -> Result<(), ChatError>;
}
