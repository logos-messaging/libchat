mod client;
mod delivery_in_process;
mod errors;
mod event;

pub use client::{ChatClient, Transport};
pub use delivery_in_process::{InProcessDelivery, MessageBus};
pub use errors::ClientError;
pub use event::Event;

// Re-export types callers need to interact with ChatClient.
pub use libchat::{
    AddressedEnvelope, ConversationClass, ConversationId, DeliveryService, RegistrationService,
    StorageConfig,
};

// Re-export bundled registry implementations so callers can pick one without
// pulling in `components` directly.
pub use components::{EphemeralRegistry, HttpRegistry, HttpRegistryError};
