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
use crate::config::{NETWORK_PRESET, REGISTRY_ENDPOINT};
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

/// A [`ChatClient`] wired to the Logos service stack: a [`DelegateSigner`]
/// identity acting for a fresh dev account, the HTTP keypackage + account
/// registry ([`HttpRegistry`], which is both the keypackage store and the
/// account → device directory), encrypted [`ChatStorage`], and the
/// logos-delivery transport.
pub type LogosChatClient = ChatClient<EmbeddedP2pDeliveryService, HttpRegistry, ChatStorage>;

impl LogosChatClient {
    /// Open a client on the Logos stack, starting a logos-delivery node on
    /// `tcp_port` as its transport and persisting to the encrypted database at
    /// `db_path` unlocked with `db_key`. When `preset`/`registry_url` are `Some`,
    /// they override the baked-in network preset/registry endpoint (e.g. a local
    /// deployment); otherwise the preconfigured values are used.
    ///
    /// `db_path` is a per-client location, `db_key` is a secret, and `tcp_port`
    /// is a per-client local resource, so all three are caller-supplied — never
    /// baked into the library.
    pub fn open(
        db_path: impl Into<String>,
        db_key: impl Into<String>,
        tcp_port: u16,
        preset: Option<&str>,
        registry_url: Option<&str>,
    ) -> Result<(Self, Receiver<Event>), ClientError> {
        let transport = EmbeddedP2pDeliveryService::start(P2pConfig {
            preset: preset.unwrap_or(NETWORK_PRESET).to_string(),
            tcp_port,
            ..Default::default()
        })
        .map_err(|e| ClientError::Transport(e.to_string()))?;

        let endpoint = registry_url.unwrap_or(REGISTRY_ENDPOINT);
        // A fresh account endorsing a fresh delegate each open: the account
        // key is dropped after publishing the bundle, so devices cannot be
        // added later. A caller-supplied, custody-holding account replaces
        // this once the platform provides one.
        let account = TestLogosAccount::new();
        let delegate = DelegateSigner::random();
        let mut registry = HttpRegistry::new(endpoint);
        account
            .add_delegate_signer(&mut registry, delegate.public_key())
            .map_err(|e| ClientError::BundlePublish(e.to_string()))?;
        ChatClientBuilder::new(account.address())
            .ident(delegate)
            .transport(transport)
            .registration(registry)
            .storage_config(StorageConfig::Encrypted {
                path: db_path.into(),
                key: db_key.into(),
            })
            .build()
    }
}
