mod builder;
mod client;
mod delegate;
mod delivery_in_process;
mod errors;
mod event;

pub use builder::{ChatClientBuilder, Unset};
pub use client::{ChatClient, Transport};
pub use delegate::DelegateSigner;
pub use delivery_in_process::{InProcessDelivery, MessageBus};
pub use errors::ClientError;
pub use event::{Event, MessageSender};

// Re-export types callers need to interact with ChatClient.
pub use libchat::{
    AddressedEnvelope, ChatStorage, ChatStore, ConversationClass, ConversationId, DeliveryService,
    IdentityProvider, RegistrationService, StorageConfig,
};

// Re-export bundled registry implementations so callers can pick one without
// pulling in `components` directly.
pub use components::{EphemeralRegistry, HttpRegistry, HttpRegistryError};
