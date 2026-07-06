//! The opinionated Logos client.
//!
//! `LogosChatClient` commits to the Logos service stack so independently built
//! clients share the same production services instead of each re-deriving them:
//! a delegate identity, the HTTP keypackage + account registry, and encrypted
//! on-disk storage. The stack is generic over the transport — any
//! [`Transport`] can be injected via
//! [`open_with_transport`](LogosChatClient::open_with_transport) — and
//! concrete Logos clients are named aliases that commit to one, each in its
//! own module (e.g. `EmbeddedLogosClient` in `crate::embedded`, behind the
//! cargo feature carrying its native dependency). This module itself compiles
//! unconditionally.

use components::HttpRegistry;
use crossbeam_channel::Receiver;
use libchat::{ChatStorage, StorageConfig};
use logos_account::TestLogosAccount;

use crate::ChatClientBuilder;
use crate::client::{ChatClient, Transport};
use crate::delegate::DelegateSigner;
use crate::errors::ClientError;
use crate::event::Event;

/// The endpoint for the account and keypackage registration service.
pub const REGISTRY_ENDPOINT: &str = "https://devnet.chat-kc.logos.co";

/// Configuration for opening a Logos client.
///
/// `db_path` (a per-client location) and `db_key` (a secret) are required and
/// never baked into the library. The registry endpoint defaults to the
/// baked-in Logos value; override it with
/// [`set_registry_url`](Self::set_registry_url). Transport settings are not
/// part of this config: they belong to the transport the caller opens the
/// client with.
pub struct LogosConfig {
    db_path: String,
    db_key: String,
    registry_url: String,
}

impl LogosConfig {
    /// Config for the required per-client `db_path` and `db_key`. The registry
    /// endpoint defaults to the baked-in Logos value; override it with
    /// [`set_registry_url`](Self::set_registry_url).
    pub fn new(db_path: impl Into<String>, db_key: impl Into<String>) -> Self {
        Self {
            db_path: db_path.into(),
            db_key: db_key.into(),
            registry_url: REGISTRY_ENDPOINT.to_string(),
        }
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
/// account → device directory), and encrypted [`ChatStorage`] — generic over
/// the transport `T`. Commit to a transport with
/// [`open_with_transport`](Self::open_with_transport), or use a concrete
/// alias like `EmbeddedLogosClient`.
pub type LogosChatClient<T> = ChatClient<T, HttpRegistry, ChatStorage>;

impl<T: Transport> LogosChatClient<T> {
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
