//! The opinionated Logos client.
//!
//! `LogosChatClient` commits to the Logos service stack so independently built
//! clients share the same production services instead of each re-deriving them:
//! a delegate identity, the HTTP keypackage + account registry, encrypted
//! on-disk storage, and — unlike the generic [`ChatClientBuilder`] — the
//! logos-delivery transport itself. logos-delivery *is* the transport for the
//! Logos client, so the caller no longer supplies one; only per-client secrets
//! (the database path and key) and the network config are passed in.
//!
//! The logos-delivery transport carries a native dependency, so this whole
//! module is gated behind the `embedded-p2p-delivery` cargo feature. The registry
//! endpoint lives in [`crate::config`] instead, so it stays available to other
//! transports when the feature is off.

use components::{EmbeddedP2pDeliveryService, HttpRegistry, P2pConfig};
use crossbeam_channel::Receiver;
use libchat::{ChatStorage, StorageConfig};
use logos_account::TestLogosAccount;

use crate::ChatClientBuilder;
use crate::client::{ChatClient, Transport};
use crate::config::{DEFAULT_TCP_PORT, NETWORK_PRESET, REGISTRY_ENDPOINT};
use crate::delegate::DelegateSigner;
use crate::errors::ClientError;
use crate::event::Event;

// logos-delivery already implements `DeliveryService`; teaching it the inbound
// half here (in the crate that owns `Transport`) makes it a full transport, so
// callers need no wrapper newtype.
impl Transport for EmbeddedP2pDeliveryService {
    fn inbound(&mut self) -> Receiver<Vec<u8>> {
        self.inbound_queue()
    }
}

/// Configuration for opening a [`LogosChatClient`].
///
/// `db_path` (a per-client location) and `db_key` (a secret) are required and
/// never baked into the library. The TCP port and the network config default to
/// the baked-in Logos values; override them with the setters (e.g. to point at a
/// local deployment).
pub struct LogosConfig {
    db_path: String,
    db_key: String,
    tcp_port: u16,
    preset: String,
    registry_url: String,
}

impl LogosConfig {
    /// Config for the required per-client `db_path` and `db_key`. The TCP port,
    /// network preset, and registry endpoint default to the baked-in Logos
    /// values; override them with [`set_tcp_port`](Self::set_tcp_port),
    /// [`set_preset`](Self::set_preset), and
    /// [`set_registry_url`](Self::set_registry_url).
    pub fn new(db_path: impl Into<String>, db_key: impl Into<String>) -> Self {
        Self {
            db_path: db_path.into(),
            db_key: db_key.into(),
            tcp_port: DEFAULT_TCP_PORT,
            preset: NETWORK_PRESET.to_string(),
            registry_url: REGISTRY_ENDPOINT.to_string(),
        }
    }

    /// Override the TCP port for the embedded logos-delivery node.
    pub fn set_tcp_port(&mut self, tcp_port: u16) {
        self.tcp_port = tcp_port;
    }

    /// Override the logos-delivery network preset (defaults to the baked-in
    /// [`NETWORK_PRESET`]).
    pub fn set_preset(&mut self, preset: impl Into<String>) {
        self.preset = preset.into();
    }

    /// Override the registry endpoint (account + keypackage store; defaults to
    /// the baked-in [`REGISTRY_ENDPOINT`]).
    pub fn set_registry_url(&mut self, registry_url: impl Into<String>) {
        self.registry_url = registry_url.into();
    }
}

/// A [`ChatClient`] wired to the Logos service stack: a [`DelegateSigner`]
/// identity acting for a fresh dev account, the HTTP keypackage + account
/// registry ([`HttpRegistry`], which is both the keypackage store and the
/// account → device directory), encrypted [`ChatStorage`], and the
/// logos-delivery transport.
pub type LogosChatClient = ChatClient<EmbeddedP2pDeliveryService, HttpRegistry, ChatStorage>;

impl LogosChatClient {
    /// Open a client on the Logos stack per `config`, starting a logos-delivery
    /// node as its transport and persisting to the encrypted database.
    pub fn open(config: LogosConfig) -> Result<(Self, Receiver<Event>), ClientError> {
        let transport = EmbeddedP2pDeliveryService::start(P2pConfig {
            preset: config.preset,
            tcp_port: config.tcp_port,
            ..Default::default()
        })
        .map_err(|e| ClientError::Transport(e.to_string()))?;

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
