//! Application-facing chat events.
//!
//! Each variant of [`Event`] describes one observable thing the application
//! cares about: a new conversation has appeared, a message was decrypted on
//! an existing one, and so on. The enum is `#[non_exhaustive]` so new
//! variants can be added without breaking exhaustive matches in dependent
//! crates.

use libchat::ConversationIdOwned;

/// A discrete chat event.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Event {
    /// A new conversation has appeared.
    ConversationStarted {
        convo_id: ConversationIdOwned,
        class: ConversationClass,
    },
    /// User content arrived on an existing conversation.
    MessageReceived {
        convo_id: ConversationIdOwned,
        content: Vec<u8>,
    },
}

/// Coarse classification of a conversation, intended as a UI/UX hint.
///
/// Decoupled from the core's protocol-versioned kinds: future versions of
/// an existing class (e.g. a `PrivateV2`) map to the same variant here.
/// New variants are reserved for fundamentally different conversation
/// shapes and are intentionally breaking when added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationClass {
    Private,
    Group,
}
