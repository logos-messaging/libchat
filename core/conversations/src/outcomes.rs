//! Observations a single inbound payload produces.
//!
//! - [`ConvoOutcome`] — an optional [`Content`] on a single existing
//!   conversation.
//! - [`InboxOutcome`] — a newly observed conversation, optionally with an
//!   initial [`ConvoOutcome`].
//! - [`PayloadOutcome`] — the union of the above, plus `Empty`.

use logos_account::SenderCredential;
use storage::ConversationKind;

use crate::conversation::ConversationId;

#[derive(Debug, Clone)]
pub struct Content {
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ConvoOutcome {
    pub convo_id: ConversationId,
    pub content: Option<Content>,
    /// The *unvalidated* sender credential for `content`: the claimed Account
    /// and the device (LocalIdentity) it was sent from. The device key is
    /// MLS-authenticated, but the account claim must be validated against an
    /// [`AccountService`](logos_account::AccountService) before it is trusted.
    /// `None` for control messages (e.g. MLS commits) carrying no application
    /// content, and for conversation types that don't yet surface a credential.
    pub credential: Option<SenderCredential>,
}

impl ConvoOutcome {
    pub fn empty(convo_id: ConversationId) -> Self {
        Self {
            convo_id,
            content: None,
            credential: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewConversation {
    pub convo_id: ConversationId,
    pub class: ConversationClass,
}

#[derive(Debug, Clone)]
pub struct InboxOutcome {
    pub new_conversation: NewConversation,
    pub initial: Option<ConvoOutcome>,
}

#[derive(Debug, Clone, Default)]
pub enum PayloadOutcome {
    #[default]
    Empty,
    Convo(ConvoOutcome),
    Inbox(InboxOutcome),
}

impl From<ConvoOutcome> for PayloadOutcome {
    fn from(c: ConvoOutcome) -> Self {
        Self::Convo(c)
    }
}

impl From<InboxOutcome> for PayloadOutcome {
    fn from(i: InboxOutcome) -> Self {
        Self::Inbox(i)
    }
}

/// Stable across protocol versions of the same conversation shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationClass {
    Private,
    Group,
}

impl ConversationClass {
    /// `Unknown(_)` yields `None`.
    pub fn from_kind(kind: &ConversationKind) -> Option<Self> {
        match kind {
            ConversationKind::PrivateV1 => Some(Self::Private),
            ConversationKind::GroupV1 => Some(Self::Group),
            ConversationKind::Unknown(_) => None,
        }
    }
}
