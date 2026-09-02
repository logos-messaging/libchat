use storage::{ConversationKind, Namespace};

use crate::ChatError;

/// The protocol that owns a piece of state; gains a variant when a protocol ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    GroupV1,
    DirectV1,
    GroupV2,
    InboxV2,
}

impl From<Protocol> for Namespace {
    fn from(protocol: Protocol) -> Self {
        Namespace::new(match protocol {
            Protocol::GroupV1 => "group_v1",
            Protocol::DirectV1 => "direct_v1",
            Protocol::GroupV2 => "group_v2",
            Protocol::InboxV2 => "inbox_v2",
        })
    }
}

/// A conversation record names the protocol whose scope holds the conversation's state.
impl TryFrom<&ConversationKind> for Protocol {
    type Error = ChatError;

    fn try_from(kind: &ConversationKind) -> Result<Self, ChatError> {
        match kind {
            ConversationKind::GroupV1 => Ok(Self::GroupV1),
            ConversationKind::DirectV1 => Ok(Self::DirectV1),
            ConversationKind::GroupV2 => Ok(Self::GroupV2),
            ConversationKind::Unknown(kind) => Err(ChatError::UnsupportedConvoType(kind.clone())),
        }
    }
}
