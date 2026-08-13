use components::EphemeralRegistry;
use crossbeam_channel::Receiver;
use libchat::{
    AuthVerifyService, ChatError, ChatStorage, GroupV2Config, RegistrationService, StorageConfig,
};
use logos_account::AccountRegistry;
use storage::ChatStore;

use crate::Transport;
use crate::client::ChatClient;
use crate::delegate::DelegateSigner;
use crate::errors::ClientError;
use crate::event::Event;

/// Marker for a builder field that has not been configured; the corresponding
/// component will be filled in with a sensible default when `build()` is called.
pub struct Unset;

pub struct ChatClientBuilder<I = Unset, AS = Unset, T = Unset, R = Unset, S = Unset> {
    ident: I,
    auth: AS,
    account: Vec<u8>,
    transport: T,
    registration: R,
    storage: S,
    group_v2: Option<GroupV2Config>,
}

impl ChatClientBuilder {
    /// Every client acts for an account, so the builder starts from its
    /// address bytes. They become the client's shareable address
    /// ([`ChatClient::addr`]) and the account claim in the wire credential;
    /// the account must endorse the signer in the directory for peers to
    /// verify that claim.
    ///
    /// A credential verifier is required before [`build`](ChatClientBuilder::build);
    /// set one with [`auth`](ChatClientBuilder::auth).
    pub fn new(account: impl Into<Vec<u8>>) -> Self {
        Self {
            ident: Unset,
            auth: Unset,
            account: account.into(),
            transport: Unset,
            registration: Unset,
            storage: Unset,
            group_v2: None,
        }
    }
}

impl<I, AS, T, R, S> ChatClientBuilder<I, AS, T, R, S> {
    pub fn ident(self, ident: DelegateSigner) -> ChatClientBuilder<DelegateSigner, AS, T, R, S> {
        ChatClientBuilder {
            ident,
            auth: self.auth,
            account: self.account,
            transport: self.transport,
            registration: self.registration,
            storage: self.storage,
            group_v2: self.group_v2,
        }
    }

    /// The credential verifier this client uses to bind a message signer to the
    /// account named in its credential. Required before [`build`](Self::build).
    pub fn auth<NAS>(self, auth: NAS) -> ChatClientBuilder<I, NAS, T, R, S> {
        ChatClientBuilder {
            ident: self.ident,
            auth,
            account: self.account,
            transport: self.transport,
            registration: self.registration,
            storage: self.storage,
            group_v2: self.group_v2,
        }
    }

    pub fn transport<NT>(self, transport: NT) -> ChatClientBuilder<I, AS, NT, R, S> {
        ChatClientBuilder {
            ident: self.ident,
            auth: self.auth,
            account: self.account,
            transport,
            registration: self.registration,
            storage: self.storage,
            group_v2: self.group_v2,
        }
    }

    pub fn registration<NR>(self, registration: NR) -> ChatClientBuilder<I, AS, T, NR, S> {
        ChatClientBuilder {
            ident: self.ident,
            auth: self.auth,
            account: self.account,
            transport: self.transport,
            registration,
            storage: self.storage,
            group_v2: self.group_v2,
        }
    }

    pub fn storage<NS>(self, storage: NS) -> ChatClientBuilder<I, AS, T, R, NS> {
        ChatClientBuilder {
            ident: self.ident,
            auth: self.auth,
            account: self.account,
            transport: self.transport,
            registration: self.registration,
            storage,
            group_v2: self.group_v2,
        }
    }

    pub fn storage_config(
        self,
        config: StorageConfig,
    ) -> ChatClientBuilder<I, AS, T, R, ChatStorage> {
        let storage = ChatStorage::new(config)
            .map_err(ChatError::from)
            .expect("Storage config file should be valid");

        ChatClientBuilder {
            ident: self.ident,
            auth: self.auth,
            account: self.account,
            transport: self.transport,
            registration: self.registration,
            storage,
            group_v2: self.group_v2,
        }
    }

    /// Timing/policy for GroupV2 conversations this client creates or joins.
    /// Defaults to the de-mls library defaults; the creator's phase durations
    /// travel to joiners with the welcome and overwrite theirs (vote delays
    /// and policy fields stay local).
    pub fn group_v2_config(mut self, config: GroupV2Config) -> Self {
        self.group_v2 = Some(config);
        self
    }
}

type Built<AS, T, R, S> = Result<(ChatClient<AS, T, R, S>, Receiver<Event>), ClientError>;

// All four explicitly provided.
impl<AS, T, R, S> ChatClientBuilder<DelegateSigner, AS, T, R, S>
where
    AS: AuthVerifyService + Send + 'static,
    T: Transport + Send + 'static,
    R: RegistrationService + AccountRegistry + Clone + Send + 'static,
    S: ChatStore + Send + 'static,
{
    pub fn build(self) -> Built<AS, T, R, S> {
        ChatClient::new(
            self.ident,
            self.auth,
            self.account,
            self.transport,
            self.registration,
            self.storage,
            self.group_v2,
        )
    }
}

// Transport only; I, R, S all default.
impl<AS, T> ChatClientBuilder<Unset, AS, T, Unset, Unset>
where
    AS: AuthVerifyService + Send + 'static,
    T: Transport + Send + 'static,
{
    pub fn build(self) -> Built<AS, T, EphemeralRegistry, ChatStorage> {
        ChatClient::new(
            DelegateSigner::random(),
            self.auth,
            self.account,
            self.transport,
            EphemeralRegistry::new(),
            ChatStorage::in_memory(),
            self.group_v2,
        )
    }
}

// I and T; R and S default.
impl<AS, T> ChatClientBuilder<DelegateSigner, AS, T, Unset, Unset>
where
    AS: AuthVerifyService + Send + 'static,
    T: Transport + Send + 'static,
{
    pub fn build(self) -> Built<AS, T, EphemeralRegistry, ChatStorage> {
        ChatClient::new(
            self.ident,
            self.auth,
            self.account,
            self.transport,
            EphemeralRegistry::new(),
            ChatStorage::in_memory(),
            self.group_v2,
        )
    }
}

// T and R; I and S default.
impl<AS, T, R> ChatClientBuilder<Unset, AS, T, R, Unset>
where
    AS: AuthVerifyService + Send + 'static,
    T: Transport + Send + 'static,
    R: RegistrationService + AccountRegistry + Clone + Send + 'static,
{
    pub fn build(self) -> Built<AS, T, R, ChatStorage> {
        ChatClient::new(
            DelegateSigner::random(),
            self.auth,
            self.account,
            self.transport,
            self.registration,
            ChatStorage::in_memory(),
            self.group_v2,
        )
    }
}

// T and S; I and R default.
impl<AS, T, S> ChatClientBuilder<Unset, AS, T, Unset, S>
where
    AS: AuthVerifyService + Send + 'static,
    T: Transport + Send + 'static,
    S: ChatStore + Send + 'static,
{
    pub fn build(self) -> Built<AS, T, EphemeralRegistry, S> {
        ChatClient::new(
            DelegateSigner::random(),
            self.auth,
            self.account,
            self.transport,
            EphemeralRegistry::new(),
            self.storage,
            self.group_v2,
        )
    }
}

// I, T, and R; S defaults.
impl<AS, T, R> ChatClientBuilder<DelegateSigner, AS, T, R, Unset>
where
    AS: AuthVerifyService + Send + 'static,
    T: Transport + Send + 'static,
    R: RegistrationService + AccountRegistry + Clone + Send + 'static,
{
    pub fn build(self) -> Built<AS, T, R, ChatStorage> {
        ChatClient::new(
            self.ident,
            self.auth,
            self.account,
            self.transport,
            self.registration,
            ChatStorage::in_memory(),
            self.group_v2,
        )
    }
}

// T, R, and S; I defaults.
impl<AS, T, R, S> ChatClientBuilder<Unset, AS, T, R, S>
where
    AS: AuthVerifyService + Send + 'static,
    T: Transport + Send + 'static,
    R: RegistrationService + AccountRegistry + Clone + Send + 'static,
    S: ChatStore + Send + 'static,
{
    pub fn build(self) -> Built<AS, T, R, S> {
        ChatClient::new(
            DelegateSigner::random(),
            self.auth,
            self.account,
            self.transport,
            self.registration,
            self.storage,
            self.group_v2,
        )
    }
}

// I, T, and S; R defaults.
impl<AS, T, S> ChatClientBuilder<DelegateSigner, AS, T, Unset, S>
where
    AS: AuthVerifyService + Send + 'static,
    T: Transport + Send + 'static,
    S: ChatStore + Send + 'static,
{
    pub fn build(self) -> Built<AS, T, EphemeralRegistry, S> {
        ChatClient::new(
            self.ident,
            self.auth,
            self.account,
            self.transport,
            EphemeralRegistry::new(),
            self.storage,
            self.group_v2,
        )
    }
}
