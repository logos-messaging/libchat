mod group_v1;

use crate::{AccountId, ContentData, DeliveryService, RegistrationService};
use chat_proto::logoschat::encryption::EncryptedPayload;
use libchat::IdentityProvider;

use std::fmt::Debug;

pub use crate::ChatError;
pub use group_v1::GroupV1Convo;

pub type ConversationIdRef<'a> = &'a str;
pub type ConversationId = String;

pub struct ServiceContext<IP: IdentityProvider, DS: DeliveryService, RS: RegistrationService> {
    pub identity_provider: IP,
    pub ds: DS,
    pub rs: RS,
}

pub trait Id: Debug {
    fn id(&self) -> ConversationIdRef<'_>;
}

pub trait BaseConvo<IP: IdentityProvider, DS: DeliveryService, RS: RegistrationService>:
    Id + Debug
{
    fn init(&self, service_ctx: &mut ServiceContext<IP, DS, RS>) -> Result<(), ChatError>;

    fn send_content(
        &mut self,
        service_ctx: &mut ServiceContext<IP, DS, RS>,
        content: &[u8],
    ) -> Result<(), ChatError>;

    fn handle_frame(
        &mut self,
        service_ctx: &mut ServiceContext<IP, DS, RS>,
        enc_payload: EncryptedPayload,
    ) -> Result<Option<ContentData>, ChatError>;
}

pub trait BaseGroupConvo<IP: IdentityProvider, DS: DeliveryService, RS: RegistrationService>:
    BaseConvo<IP, DS, RS>
{
    fn add_member(
        &mut self,
        service_ctx: &mut ServiceContext<IP, DS, RS>,
        members: &[&AccountId],
    ) -> Result<(), ChatError>;
}
