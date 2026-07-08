mod embedded;
mod logos;

pub use embedded::LogosChatClient;
pub use logos::{LogosChatClientInternal, LogosConfig, REGISTRY_ENDPOINT};
// Facade re-exports so callers need no direct dependency on the transport
// crate.
pub use embedded_logos_delivery::{
    DEFAULT_NETWORK_PRESET, DEFAULT_TCP_PORT, EmbeddedLogosDelivery, P2pConfig,
};

// Re-export the transport-generic client surface so callers depend on this
// crate alone.
pub use logos_generic_chat::*;
