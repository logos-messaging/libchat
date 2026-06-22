use components::EphemeralRegistry;
use crossbeam_channel::Receiver;
use libchat::{ChatError, ChatStorage, IdentityProvider, RegistrationService, StorageConfig};
use storage::ChatStore;

use crate::Transport;
use crate::client::ChatClient;
use crate::delegate::DelegateSigner;
use crate::errors::ClientError;
use crate::event::Event;

/// Marker for a builder field that has not been configured; the corresponding
/// component will be filled in with a sensible default when `build()` is called.
pub struct Unset;

pub struct ChatClientBuilder<I = Unset, T = Unset, R = Unset, S = Unset> {
    ident: I,
    transport: T,
    registration: R,
    storage: S,
}

impl Default for ChatClientBuilder {
    fn default() -> Self {
        Self {
            ident: Unset,
            transport: Unset,
            registration: Unset,
            storage: Unset,
        }
    }
}

impl ChatClientBuilder {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<I, T, R, S> ChatClientBuilder<I, T, R, S> {
    pub fn ident<NI>(self, ident: NI) -> ChatClientBuilder<NI, T, R, S> {
        ChatClientBuilder {
            ident,
            transport: self.transport,
            registration: self.registration,
            storage: self.storage,
        }
    }

    pub fn transport<NT>(self, transport: NT) -> ChatClientBuilder<I, NT, R, S> {
        ChatClientBuilder {
            ident: self.ident,
            transport,
            registration: self.registration,
            storage: self.storage,
        }
    }

    pub fn registration<NR>(self, registration: NR) -> ChatClientBuilder<I, T, NR, S> {
        ChatClientBuilder {
            ident: self.ident,
            transport: self.transport,
            registration,
            storage: self.storage,
        }
    }

    pub fn storage<NS>(self, storage: NS) -> ChatClientBuilder<I, T, R, NS> {
        ChatClientBuilder {
            ident: self.ident,
            transport: self.transport,
            registration: self.registration,
            storage,
        }
    }

    pub fn storage_config(self, config: StorageConfig) -> ChatClientBuilder<I, T, R, ChatStorage> {
        let storage = ChatStorage::new(config)
            .map_err(ChatError::from)
            .expect("Storage config file should be valid");

        ChatClientBuilder {
            ident: self.ident,
            transport: self.transport,
            registration: self.registration,
            storage,
        }
    }
}

type Built<I, T, R, S> = Result<(ChatClient<I, T, R, S>, Receiver<Event>), ClientError>;

// All four explicitly provided.
impl<I, T, R, S> ChatClientBuilder<I, T, R, S>
where
    I: IdentityProvider + Send + 'static,
    T: Transport + Send + 'static,
    R: RegistrationService + Send + 'static,
    S: ChatStore + Send + 'static,
{
    pub fn build(self) -> Built<I, T, R, S> {
        ChatClient::new(self.ident, self.transport, self.registration, self.storage)
    }
}

// Transport only; I, R, S all default.
impl<T: Transport + Send + 'static> ChatClientBuilder<Unset, T, Unset, Unset> {
    pub fn build(self) -> Built<DelegateSigner, T, EphemeralRegistry, ChatStorage> {
        ChatClient::new(
            DelegateSigner::random(),
            self.transport,
            EphemeralRegistry::new(),
            ChatStorage::in_memory(),
        )
    }
}

// I and T; R and S default.
impl<I, T> ChatClientBuilder<I, T, Unset, Unset>
where
    I: IdentityProvider + Send + 'static,
    T: Transport + Send + 'static,
{
    pub fn build(self) -> Built<I, T, EphemeralRegistry, ChatStorage> {
        ChatClient::new(
            self.ident,
            self.transport,
            EphemeralRegistry::new(),
            ChatStorage::in_memory(),
        )
    }
}

// T and R; I and S default.
impl<T, R> ChatClientBuilder<Unset, T, R, Unset>
where
    T: Transport + Send + 'static,
    R: RegistrationService + Send + 'static,
{
    pub fn build(self) -> Built<DelegateSigner, T, R, ChatStorage> {
        ChatClient::new(
            DelegateSigner::random(),
            self.transport,
            self.registration,
            ChatStorage::in_memory(),
        )
    }
}

// T and S; I and R default.
impl<T, S> ChatClientBuilder<Unset, T, Unset, S>
where
    T: Transport + Send + 'static,
    S: ChatStore + Send + 'static,
{
    pub fn build(self) -> Built<DelegateSigner, T, EphemeralRegistry, S> {
        ChatClient::new(
            DelegateSigner::random(),
            self.transport,
            EphemeralRegistry::new(),
            self.storage,
        )
    }
}

// I, T, and R; S defaults.
impl<I, T, R> ChatClientBuilder<I, T, R, Unset>
where
    I: IdentityProvider + Send + 'static,
    T: Transport + Send + 'static,
    R: RegistrationService + Send + 'static,
{
    pub fn build(self) -> Built<I, T, R, ChatStorage> {
        ChatClient::new(
            self.ident,
            self.transport,
            self.registration,
            ChatStorage::in_memory(),
        )
    }
}

// T, R, and S; I defaults.
impl<T, R, S> ChatClientBuilder<Unset, T, R, S>
where
    T: Transport + Send + 'static,
    R: RegistrationService + Send + 'static,
    S: ChatStore + Send + 'static,
{
    pub fn build(self) -> Built<DelegateSigner, T, R, S> {
        ChatClient::new(
            DelegateSigner::random(),
            self.transport,
            self.registration,
            self.storage,
        )
    }
}

// I, T, and S; R defaults.
impl<I, T, S> ChatClientBuilder<I, T, Unset, S>
where
    I: IdentityProvider + Send + 'static,
    T: Transport + Send + 'static,
    S: ChatStore + Send + 'static,
{
    pub fn build(self) -> Built<I, T, EphemeralRegistry, S> {
        ChatClient::new(
            self.ident,
            self.transport,
            EphemeralRegistry::new(),
            self.storage,
        )
    }
}
