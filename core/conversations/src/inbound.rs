//! Outcome of processing a single inbound payload.
//!
//! [`InboundResult`] composes two layers:
//! - [`FrameOutcome`] captures what processing one frame within a conversation
//!   produces: today, decrypted messages. As protocol features land, new
//!   per-conversation observations (e.g. group membership changes) become
//!   additive fields on `FrameOutcome`.
//! - [`InboundResult`] wraps a `FrameOutcome` and adds the payload-level
//!   observations a single frame cannot produce — today, the appearance of
//!   a new conversation from the peer side.

use storage::ConversationKind;

use crate::context::ConversationIdOwned;

/// Observations a conversation produces from processing one frame.
#[derive(Debug, Clone, Default)]
pub struct FrameOutcome {
    /// User content decrypted from this frame, in protocol order.
    pub messages: Vec<Message>,
}

impl FrameOutcome {
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// Everything one inbound payload produced.
#[derive(Debug, Clone, Default)]
pub struct InboundResult {
    /// A new conversation appeared from this payload, if any.
    pub new_conversation: Option<NewConversation>,
    /// Observations from the frame inside this payload.
    pub frame: FrameOutcome,
}

impl InboundResult {
    /// True when the payload produced no observable outcome.
    pub fn is_empty(&self) -> bool {
        self.new_conversation.is_none() && self.frame.is_empty()
    }
}

/// A conversation newly observed from the peer side.
#[derive(Debug, Clone)]
pub struct NewConversation {
    pub convo_id: ConversationIdOwned,
    pub kind: ConversationKind,
}

/// User content decrypted from an inbound payload.
#[derive(Debug, Clone)]
pub struct Message {
    pub convo_id: ConversationIdOwned,
    pub content: Vec<u8>,
}
