//! Baked-in configuration for the Logos service stack.

/// The endpoint for the account and keypackage registration service.
pub const REGISTRY_ENDPOINT: &str = "https://devnet.chat-kc.logos.co";

/// The logos-delivery network preset the Logos client joins by default.
pub const NETWORK_PRESET: &str = "logos.dev";

/// Default TCP port for the embedded logos-delivery node.
pub const DEFAULT_TCP_PORT: u16 = 60000;
