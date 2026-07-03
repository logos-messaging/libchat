mod builder;
mod client;
mod config;
mod delegate;
mod delivery_in_process;
mod errors;
mod event;
#[cfg(feature = "embedded-p2p-delivery")]
mod logos;

pub use builder::{ChatClientBuilder, Unset};
pub use client::{ChatClient, Transport};
pub use config::{NETWORK_PRESET, REGISTRY_ENDPOINT};
pub use delegate::DelegateSigner;
pub use delivery_in_process::{InProcessDelivery, MessageBus};
pub use errors::ClientError;
pub use event::{Event, MessageSender};
#[cfg(feature = "embedded-p2p-delivery")]
pub use logos::LogosChatClient;

// Re-export types callers need to interact with ChatClient.
pub use libchat::{
    AddressedEnvelope, ChatStore, ConversationClass, ConversationId, DeliveryService,
    IdentityProvider, RegistrationService, StorageConfig,
};
// The directory trait bounds ChatClient's registry parameter, so callers
// writing code generic over ChatClient need it too.
pub use logos_account::AccountDirectory;

// Re-export bundled registry implementations so callers can pick one without
// pulling in `components` directly.
pub use components::{EphemeralRegistry, HttpRegistry, HttpRegistryError};
