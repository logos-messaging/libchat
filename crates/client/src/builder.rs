use components::EphemeralRegistry;
use crossbeam_channel::Receiver;
use libchat::{ChatError, ChatStorage, IdentityProvider, RegistrationService, StorageConfig};

use crate::Transport;
use crate::client::ChatClient;
use crate::delegate::DelegateSigner;
use crate::errors::ClientError;
use crate::event::Event;

/// Marker for a builder field that has not been configured; the corresponding
/// component will be filled in with a sensible default when `build()` is called.
pub struct Unset;

pub struct ChatClientBuilder<I = Unset, T = Unset, R = Unset> {
    ident: I,
    transport: T,
    registration: R,
    /// The durable store; defaults to an ephemeral in-memory `ChatStorage` at
    /// `build()` when left unset by [`storage`](Self::storage) or
    /// [`storage_config`](Self::storage_config).
    storage: Option<ChatStorage>,
}

impl Default for ChatClientBuilder {
    fn default() -> Self {
        Self {
            ident: Unset,
            transport: Unset,
            registration: Unset,
            storage: None,
        }
    }
}

impl ChatClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<I, T, R> ChatClientBuilder<I, T, R> {
    pub fn ident<NI>(self, ident: NI) -> ChatClientBuilder<NI, T, R> {
        ChatClientBuilder {
            ident,
            transport: self.transport,
            registration: self.registration,
            storage: self.storage,
        }
    }

    pub fn transport<NT>(self, transport: NT) -> ChatClientBuilder<I, NT, R> {
        ChatClientBuilder {
            ident: self.ident,
            transport,
            registration: self.registration,
            storage: self.storage,
        }
    }

    pub fn registration<NR>(self, registration: NR) -> ChatClientBuilder<I, T, NR> {
        ChatClientBuilder {
            ident: self.ident,
            transport: self.transport,
            registration,
            storage: self.storage,
        }
    }

    pub fn storage(mut self, storage: ChatStorage) -> Self {
        self.storage = Some(storage);
        self
    }

    pub fn storage_config(mut self, config: StorageConfig) -> Self {
        let storage = ChatStorage::new(config)
            .map_err(ChatError::from)
            .expect("Storage config file should be valid");
        self.storage = Some(storage);
        self
    }
}

type Built<I, T, R> = Result<(ChatClient<I, T, R>, Receiver<Event>), ClientError>;

// I and R explicitly provided.
impl<I, T, R> ChatClientBuilder<I, T, R>
where
    I: IdentityProvider + Send + 'static,
    T: Transport + Send + 'static,
    R: RegistrationService + Send + 'static,
{
    pub fn build(self) -> Built<I, T, R> {
        ChatClient::new(
            self.ident,
            self.transport,
            self.registration,
            self.storage.unwrap_or_else(ChatStorage::in_memory),
        )
    }
}

// Transport only; I and R default.
impl<T: Transport + Send + 'static> ChatClientBuilder<Unset, T, Unset> {
    pub fn build(self) -> Built<DelegateSigner, T, EphemeralRegistry> {
        ChatClient::new(
            DelegateSigner::random(),
            self.transport,
            EphemeralRegistry::new(),
            self.storage.unwrap_or_else(ChatStorage::in_memory),
        )
    }
}

// I and T; R defaults.
impl<I, T> ChatClientBuilder<I, T, Unset>
where
    I: IdentityProvider + Send + 'static,
    T: Transport + Send + 'static,
{
    pub fn build(self) -> Built<I, T, EphemeralRegistry> {
        ChatClient::new(
            self.ident,
            self.transport,
            EphemeralRegistry::new(),
            self.storage.unwrap_or_else(ChatStorage::in_memory),
        )
    }
}

// T and R; I defaults.
impl<T, R> ChatClientBuilder<Unset, T, R>
where
    T: Transport + Send + 'static,
    R: RegistrationService + Send + 'static,
{
    pub fn build(self) -> Built<DelegateSigner, T, R> {
        ChatClient::new(
            DelegateSigner::random(),
            self.transport,
            self.registration,
            self.storage.unwrap_or_else(ChatStorage::in_memory),
        )
    }
}
