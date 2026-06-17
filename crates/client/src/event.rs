//! Application-facing chat events.
//!
//! Each variant of [`Event`] describes one observable thing the application
//! cares about: a new conversation has appeared, a message was decrypted on
//! an existing one, and so on. The enum is `#[non_exhaustive]` so new
//! variants can be added without breaking exhaustive matches in dependent
//! crates.

use std::sync::Arc;

use libchat::{ConversationClass, MessageSender};

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
        /// The verified sender — both the Account and the LocalIdentity
        /// (device) it was sent from. `None` when the conversation type does
        /// not yet surface a sender.
        sender: Option<MessageSender>,
    },
    InboundError {
        message: String,
    },
}
