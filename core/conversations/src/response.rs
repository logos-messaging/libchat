//! Outcome of processing a single inbound payload.
//!
//! [`ProcessResponse`] is the tagged sum of what a payload produced, one
//! variant per dispatch destination (inbox, existing conversation, unknown).
//! [`FrameOutcome`] captures what processing one frame within a conversation
//! produces: today, a decrypted message. As protocol features land, new
//! per-conversation observations become additive fields on `FrameOutcome`.
//!
//! [`InboxResponse::frame`] is `None` when the inbox produced a new conversation
//! without an initial message (V2 invite); `Some` when an initial message was
//! delivered alongside the invite (V1).

use storage::ConversationKind;

use crate::causal_history::MissingMessage;
use crate::context::ConversationIdOwned;

/// Observations a conversation produces from processing one frame.
#[derive(Debug, Clone, Default)]
pub struct FrameOutcome {
    /// User content decrypted from this frame, in protocol order.
    pub message: Option<Message>,
    /// Causal-history gaps detected from this frame's piggybacked history.
    /// Empty for protocols without causal history (e.g. PrivateV1) and for
    /// frames that close no gaps.
    pub missing_messages: Vec<MissingMessage>,
}

#[derive(Debug, Clone)]
pub enum ProcessResponse {
    InboxResponse(InboxResponse),
    ConvoResponse(ConvoResponse),
    Unknown,
}

#[derive(Debug, Clone)]
pub struct InboxResponse {
    /// A new conversation appeared from this payload, if any.
    pub new_conversation: NewConversation,
    /// Observations from the frame inside this payload.
    pub frame: Option<FrameOutcome>,
}

#[derive(Debug, Clone, Default)]
pub struct ConvoResponse {
    /// Observations from the frame inside this payload.
    pub frame: FrameOutcome,
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
