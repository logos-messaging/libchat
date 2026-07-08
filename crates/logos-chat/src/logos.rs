//! The opinionated Logos client.
//!
//! `LogosChatClientInternal` commits to the Logos service stack so
//! independently built clients share the same production services instead of
//! each re-deriving them: a delegate identity, the HTTP keypackage + account
//! registry, and encrypted on-disk storage. The stack is generic over the
//! transport — any [`Transport`] can be injected via
//! [`LogosConfig::open_with_transport`] — and concrete Logos clients are
//! named aliases that commit to one, each in its own module (e.g.
//! [`LogosChatClient`](crate::LogosChatClient) in `crate::embedded`).
//!
//! The client aliases point at `ChatClient`, which lives in
//! `logos-generic-chat`, so Rust's inherent-impl rule keeps the open
//! constructors off the aliases; they hang on [`LogosConfig`] (owned here)
//! instead.

use components::HttpRegistry;
use crossbeam_channel::Receiver;
use libchat::{ChatStorage, StorageConfig};
use logos_account::TestLogosAccount;

use logos_generic_chat::{
    ChatClient, ChatClientBuilder, ClientError, DelegateSigner, Event, Transport,
};

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

    /// Open a client on the Logos stack per this config with the injected
    /// transport, persisting to the encrypted database.
    pub fn open_with_transport<T: Transport>(
        self,
        transport: T,
    ) -> Result<(LogosChatClientInternal<T>, Receiver<Event>), ClientError> {
        // A fresh account endorsing a fresh delegate each open: the account
        // key is dropped after publishing the bundle, so devices cannot be
        // added later. A caller-supplied, custody-holding account replaces
        // this once the platform provides one.
        let account = TestLogosAccount::new();
        let delegate = DelegateSigner::random();
        let mut registry = HttpRegistry::new(self.registry_url);
        account
            .add_delegate_signer(&mut registry, delegate.public_key())
            .map_err(|e| ClientError::BundlePublish(e.to_string()))?;
        ChatClientBuilder::new(account.address())
            .ident(delegate)
            .transport(transport)
            .registration(registry)
            .storage_config(StorageConfig::Encrypted {
                path: self.db_path,
                key: self.db_key,
            })
            .build()
    }
}

/// A [`ChatClient`] wired to the Logos service stack: a [`DelegateSigner`]
/// identity acting for a fresh dev account, the HTTP keypackage + account
/// registry ([`HttpRegistry`], which is both the keypackage store and the
/// account → device directory), and encrypted [`ChatStorage`] — generic over
/// the transport `T`. Commit to a transport with
/// [`LogosConfig::open_with_transport`], or use a concrete alias like
/// [`LogosChatClient`](crate::LogosChatClient).
pub type LogosChatClientInternal<T> = ChatClient<T, HttpRegistry, ChatStorage>;
