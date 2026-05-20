mod client;
mod delivery_in_process;
mod errors;

pub use client::ChatClient;
pub use delivery_in_process::{Cursor, InProcessDelivery, MessageBus};
pub use errors::ClientError;

// Re-export types callers need to interact with ChatClient
pub use libchat::{
    AddressedEnvelope, ConversationIdOwned, DeliveryService, EnvelopeId, Event, FailureReason,
    StorageConfig, drain_inbound,
};
