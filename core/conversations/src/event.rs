//! Observable events surfaced to the application layer. See
//! `docs/adr/0001-client-event-system.md`.

use crate::conversation::ConversationIdOwned;

/// Opaque correlation handle for outbound envelopes. Reserved for future
/// delivery-receipt support; no path produces a non-`None` value yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnvelopeId([u8; 16]);

impl EnvelopeId {
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Event {
    #[non_exhaustive]
    ConversationStarted {
        conversation_id: ConversationIdOwned,
    },
    #[non_exhaustive]
    MessageReceived {
        conversation_id: ConversationIdOwned,
        data: Vec<u8>,
    },
    #[non_exhaustive]
    DeliveryFailed {
        conversation_id: ConversationIdOwned,
        /// `None` when the failure isn't tied to a specific outbound envelope.
        envelope_id: Option<EnvelopeId>,
        reason: FailureReason,
    },
}

impl Event {
    pub fn transport_failure(conversation_id: ConversationIdOwned) -> Self {
        Self::DeliveryFailed {
            conversation_id,
            envelope_id: None,
            reason: FailureReason::Transport,
        }
    }

    pub fn is_delivery_failure(&self) -> bool {
        matches!(self, Self::DeliveryFailed { .. })
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum FailureReason {
    Transport,
}
