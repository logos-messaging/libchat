//! The opinionated Logos client.
//!
//! `LogosChatClient` commits to the Logos service stack so independently built
//! clients share the same production services instead of each re-deriving them:
//! a delegate identity, the HTTP keypackage + account registry, and encrypted
//! on-disk storage. The stack is generic over the transport — any
//! [`Transport`] can be injected via
//! [`open_with_transport`](LogosChatClient::open_with_transport) — and
//! concrete Logos clients are named aliases that commit to one:
//!
//! - `EmbeddedLogosClient` runs an embedded logos-delivery node in-process.
//!   The node links the native `liblogosdelivery` (from the
//!   `embedded-logos-delivery` crate), so this client — the `Transport` impl,
//!   the node fields of [`LogosConfig`], and its `open` constructor — sits
//!   behind the `embedded-logos-delivery` cargo feature, which just switches
//!   on that optional dependency. Everything else in this module compiles
//!   unconditionally.

use components::HttpRegistry;
use crossbeam_channel::Receiver;
#[cfg(feature = "embedded-logos-delivery")]
use embedded_logos_delivery::{EmbeddedLogosDelivery, P2pConfig};
use libchat::{ChatStorage, StorageConfig};
use logos_account::TestLogosAccount;

use crate::ChatClientBuilder;
use crate::client::{ChatClient, Transport};
use crate::config::REGISTRY_ENDPOINT;
#[cfg(feature = "embedded-logos-delivery")]
use crate::config::{DEFAULT_TCP_PORT, NETWORK_PRESET};
use crate::delegate::DelegateSigner;
use crate::errors::ClientError;
use crate::event::Event;

/// Configuration for opening a Logos client.
///
/// `db_path` (a per-client location) and `db_key` (a secret) are required and
/// never baked into the library. The registry endpoint defaults to the
/// baked-in Logos value; override it with
/// [`set_registry_url`](Self::set_registry_url). With the
/// `embedded-logos-delivery` feature, the config also carries the embedded
/// node's TCP port and network preset.
pub struct LogosConfig {
    db_path: String,
    db_key: String,
    registry_url: String,
    #[cfg(feature = "embedded-logos-delivery")]
    tcp_port: u16,
    #[cfg(feature = "embedded-logos-delivery")]
    preset: String,
}

impl LogosConfig {
    /// Config for the required per-client `db_path` and `db_key`. Everything
    /// else defaults to the baked-in Logos values; override with the setters.
    pub fn new(db_path: impl Into<String>, db_key: impl Into<String>) -> Self {
        Self {
            db_path: db_path.into(),
            db_key: db_key.into(),
            registry_url: REGISTRY_ENDPOINT.to_string(),
            #[cfg(feature = "embedded-logos-delivery")]
            tcp_port: DEFAULT_TCP_PORT,
            #[cfg(feature = "embedded-logos-delivery")]
            preset: NETWORK_PRESET.to_string(),
        }
    }

    /// Override the registry endpoint (account + keypackage store; defaults to
    /// the baked-in [`REGISTRY_ENDPOINT`]).
    pub fn set_registry_url(&mut self, registry_url: impl Into<String>) {
        self.registry_url = registry_url.into();
    }

    /// Override the TCP port for the embedded logos-delivery node.
    #[cfg(feature = "embedded-logos-delivery")]
    pub fn set_tcp_port(&mut self, tcp_port: u16) {
        self.tcp_port = tcp_port;
    }

    /// Override the logos-delivery network preset (defaults to the baked-in
    /// [`NETWORK_PRESET`]).
    #[cfg(feature = "embedded-logos-delivery")]
    pub fn set_preset(&mut self, preset: impl Into<String>) {
        self.preset = preset.into();
    }
}

/// A [`ChatClient`] wired to the Logos service stack: a [`DelegateSigner`]
/// identity acting for a fresh dev account, the HTTP keypackage + account
/// registry ([`HttpRegistry`], which is both the
/// keypackage store and the account → device directory), and encrypted
/// [`ChatStorage`] — generic over the transport `T`. Commit to a transport
/// with [`open_with_transport`](Self::open_with_transport), or use a concrete
/// alias like `EmbeddedLogosClient`.
pub type LogosChatClient<T> = ChatClient<T, HttpRegistry, ChatStorage>;

impl<T: Transport> ChatClient<T, HttpRegistry, ChatStorage> {
    /// Open a client on the Logos stack per `config` with the injected
    /// transport, persisting to the encrypted database.
    pub fn open_with_transport(
        config: LogosConfig,
        transport: T,
    ) -> Result<(Self, Receiver<Event>), ClientError> {
        // A fresh account endorsing a fresh delegate each open: the account
        // key is dropped after publishing the bundle, so devices cannot be
        // added later. A caller-supplied, custody-holding account replaces
        // this once the platform provides one.
        let account = TestLogosAccount::new();
        let delegate = DelegateSigner::random();
        let mut registry = HttpRegistry::new(config.registry_url);
        account
            .add_delegate_signer(&mut registry, delegate.public_key())
            .map_err(|e| ClientError::BundlePublish(e.to_string()))?;
        ChatClientBuilder::new(account.address())
            .ident(delegate)
            .transport(transport)
            .registration(registry)
            .storage_config(StorageConfig::Encrypted {
                path: config.db_path,
                key: config.db_key,
            })
            .build()
    }
}

// The embedded service implements `DeliveryService` in its own crate; teaching
// it the inbound half here (in the crate that owns `Transport`) makes it a
// full transport, so callers need no wrapper newtype.
#[cfg(feature = "embedded-logos-delivery")]
impl Transport for EmbeddedLogosDelivery {
    fn inbound(&mut self) -> Receiver<Vec<u8>> {
        self.inbound_queue()
    }
}

/// The Logos client running an embedded logos-delivery node as its transport.
/// logos-delivery is *the* production transport for Logos clients, so the
/// caller supplies only per-client secrets (the database path and key) and the
/// network config; [`open`](Self::open) starts the node itself.
#[cfg(feature = "embedded-logos-delivery")]
pub type EmbeddedLogosClient = LogosChatClient<EmbeddedLogosDelivery>;

#[cfg(feature = "embedded-logos-delivery")]
impl ChatClient<EmbeddedLogosDelivery, HttpRegistry, ChatStorage> {
    /// Open a client on the Logos stack per `config`, starting an embedded
    /// logos-delivery node as its transport.
    pub fn open(config: LogosConfig) -> Result<(Self, Receiver<Event>), ClientError> {
        let transport = EmbeddedLogosDelivery::start(P2pConfig {
            preset: config.preset.clone(),
            tcp_port: config.tcp_port,
            ..Default::default()
        })
        .map_err(|e| ClientError::Transport(e.to_string()))?;
        Self::open_with_transport(config, transport)
    }
}
