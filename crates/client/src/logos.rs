//! The opinionated Logos client.
//!
//! [`ChatClientBuilder`] is generic and can only default the zero-config
//! components (random identity, ephemeral registry, in-memory storage) — it has
//! no way to know a registry endpoint or a database path, so its defaults are
//! the test-grade ones. `LogosChatClient` is the layer that *does* commit to a
//! stack: a delegate identity, the HTTP keypackage + account registry, and
//! encrypted on-disk storage. It exists so independently built clients share the
//! same production services instead of each re-deriving them.
//!
//! Only the transport is left to the caller: it carries native dependencies and
//! environment-specific configuration that belong to the binary, not here.

use crossbeam_channel::Receiver;
use libchat::StorageConfig;

use crate::ChatClientBuilder;
use crate::client::{ChatClient, Transport};
use crate::delegate::DelegateSigner;
use crate::errors::ClientError;
use crate::event::Event;
use components::HttpRegistry;

// The endpoint for account and keypackage registration service.
const REGISTRY_ENDPOINT: &str = "https://devnet.chat-kc.logos.co";

/// A [`ChatClient`] wired to the Logos service stack: a [`DelegateSigner`]
/// identity, the HTTP keypackage + account registry ([`HttpRegistry`], which is
/// both the keypackage store and the account → device directory), and encrypted
/// [`ChatStorage`](libchat::ChatStorage). Only the transport `T` is supplied by
/// the caller.
pub type LogosChatClient<T> = ChatClient<DelegateSigner, T, HttpRegistry>;

impl<T> LogosChatClient<T>
where
    T: Transport + Send + 'static,
{
    /// Open a client on the Logos stack over `transport`, persisting to the
    /// encrypted database at `db_path` unlocked with `db_key`. When `registry_url`
    /// is `Some`, it overrides the preconfigured registry endpoint (e.g. a local
    /// deployment); otherwise the baked-in endpoint is used.
    ///
    /// `db_path` is a per-client location and `db_key` is a secret, so both are
    /// caller-supplied — never baked into the library.
    pub fn open(
        transport: T,
        db_path: impl Into<String>,
        db_key: impl Into<String>,
        registry_url: Option<&str>,
    ) -> Result<(Self, Receiver<Event>), ClientError> {
        let endpoint = registry_url.unwrap_or(REGISTRY_ENDPOINT);
        ChatClientBuilder::new()
            .ident(DelegateSigner::random())
            .transport(transport)
            .registration(HttpRegistry::new(endpoint))
            .storage_config(StorageConfig::Encrypted {
                path: db_path.into(),
                key: db_key.into(),
            })
            .build()
    }
}
