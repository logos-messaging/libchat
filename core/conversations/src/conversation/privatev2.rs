use chat_proto::logoschat::encryption::EncryptedPayload;
use shared_traits::IdentIdRef;

use crate::{
    ChatError, ExternalServices,
    conversation::{ConversationIdRef, Convo, GroupConvo, GroupV1Convo, Identified},
    service_context::ServiceContext,
};

type DelegateGroup = GroupV1Convo;

#[derive(Debug)]
pub struct PrivateV2Convo {
    inner_group: DelegateGroup,
}

impl PrivateV2Convo {
    pub fn new<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        participant: IdentIdRef,
    ) -> Result<Self, ChatError> {
        let mut inner_group = DelegateGroup::new(cx)?;
        inner_group.add_member(cx, &[participant])?;
        Ok(Self { inner_group })
    }
}

impl Identified for PrivateV2Convo {
    fn id(&self) -> ConversationIdRef<'_> {
        self.inner_group.id()
    }
}

impl<S> Convo<S> for PrivateV2Convo
where
    S: ExternalServices,
{
    fn send_content(
        &mut self,
        cx: &mut ServiceContext<S>,
        content: &[u8],
    ) -> Result<(), super::ChatError> {
        self.inner_group.send_content(cx, content)
    }

    fn handle_frame(
        &mut self,
        cx: &mut ServiceContext<S>,
        enc: EncryptedPayload,
    ) -> Result<crate::ConvoOutcome, ChatError> {
        self.inner_group.handle_frame(cx, enc)
    }

    fn wakeup(&mut self, service_ctx: &mut ServiceContext<S>) -> Result<(), ChatError> {
        self.inner_group.wakeup(service_ctx)
    }
}
