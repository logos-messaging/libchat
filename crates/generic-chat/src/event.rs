//! Application-facing chat events.
//!
//! Each variant of [`Event`] describes one observable thing the application
//! cares about: a new conversation has appeared, a message was decrypted on
//! an existing one, and so on. The enum is `#[non_exhaustive]` so new
//! variants can be added without breaking exhaustive matches in dependent
//! crates.

use std::sync::Arc;

use libchat::{ConversationClass, IdentId};

/// The sender of a received message, recovered from its credential.
///
/// `account` is present only when the sender associated an account *and* the
/// account → device directory confirmed this device belongs to it — spoofed or
/// unconfirmable claims never reach the application, so a `Some` account is
/// always verified. `local_identity` is the sending device (delegate key),
/// hex-encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSender {
    pub account: Option<IdentId>,
    pub local_identity: IdentId,
}

/// A discrete chat event.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Event {
    /// A new conversation has appeared.
    ConversationStarted {
        convo_id: Arc<str>,
        class: ConversationClass,
    },
    /// User content arrived on an existing conversation.
    MessageReceived {
        convo_id: Arc<str>,
        content: Vec<u8>,
        sender: MessageSender,
    },
    /// A message this client never received, revealed by the causal history of
    /// one that did arrive. Detection only — nothing is fetched or replayed,
    /// and the gap is reported once.
    ///
    /// `sender_hint` is the author the *referencing* peer named, resolved the
    /// same way as [`Self::MessageReceived`]'s sender but **not authenticated**:
    /// nothing about a message we never saw can be verified, so treat it as a
    /// display hint. `None` when the hint could not be resolved to a device.
    MessageMissing {
        convo_id: Arc<str>,
        message_id: String,
        sender_hint: Option<MessageSender>,
    },
    /// A commit changed a conversation's membership.
    ConversationMembersChanged {
        convo_id: Arc<str>,
    },
    InboundError {
        message: String,
    },
}
