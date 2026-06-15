use crate::causal_history::{CausalHistoryStore, MissingMessage};
use crate::conversation::{ConversationIdRef, GroupV1Convo, GroupV2Convo, PrivateV1Convo};
use crate::service_context::{ExternalServices, ServiceContext};
use crate::{DeliveryService, IdentityProvider, RegistrationService, WakeupService};
use crate::{
    conversation::{Convo, GroupConvo},
    errors::ChatError,
    inbox::Inbox,
    inbox_v2::{InboxV2, MlsEphemeralPqProvider, MlsIdentityProvider},
    outcomes::{ConvoOutcome, InboxOutcome, PayloadOutcome},
    proto::{EncryptedPayload, EnvelopeV1, Message},
};
use crypto::{Identity, PublicKey};
use openmls::group::GroupId;
use shared_traits::IdentIdRef;
use std::collections::HashMap;
use storage::{ChatStore, ConversationKind, ConversationStore};
use tracing::{info, instrument};

pub use crate::conversation::ConversationId;
pub use crate::inbox::Introduction;

// This is the main entry point to the conversations api.
// `Core` manages lifetimes of objects to process and generate payloads.
//
// Fully synchronous and single-threaded: it owns its services outright (no
// interior mutability, no shared ownership) and drives the inbox/conversation
// primitives with plain `&mut self`.
pub struct Core<S: ExternalServices> {
    services: ServiceContext<S>,
    inbox: Inbox,
    pq_inbox: InboxV2,
    // Cache of loaded conversations
    cached_convos: HashMap<String, ConvoTypeOwned<S>>,
}

// Constructors live on the `(DS, RS, CS)` form: `S` can't be inferred backwards
// through `S::DS`, so the bundle is built from the three args here.
impl<IP, DS, RS, WS, CS> Core<(IP, DS, RS, WS, CS)>
where
    IP: IdentityProvider + 'static,
    DS: DeliveryService + 'static,
    RS: RegistrationService + 'static,
    WS: WakeupService + 'static,
    CS: ChatStore + 'static,
{
    /// Opens or creates a `Core` with the given storage configuration.
    ///
    /// If an identity exists in storage, it will be restored.
    /// Otherwise, a new identity will be created with the given name and saved.
    pub fn new_from_store(
        ident: IP,
        delivery: DS,
        registration: RS,
        wakeup_service: WS,
        mut store: CS,
    ) -> Result<Self, ChatError> {
        let identity = if let Some(identity) = store.load_identity()? {
            identity
        } else {
            let identity = Identity::new(ident.id().as_str().to_string());
            store.save_identity(&identity)?;
            identity
        };

        Self::assemble(
            ident,
            identity,
            delivery,
            registration,
            wakeup_service,
            store,
        )
    }

    /// Creates a new in-memory `Core` (for testing).
    ///
    /// Uses in-memory SQLite database. Each call creates a new isolated database.
    pub fn new_with_name(
        ident: IP,
        delivery: DS,
        registration: RS,
        wakeup_service: WS,
        store: CS,
    ) -> Result<Self, ChatError> {
        let identity = Identity::new(ident.id().as_str().to_string());
        let mut core = Self::assemble(
            ident,
            identity,
            delivery,
            registration,
            wakeup_service,
            store,
        )?;

        core.register_keypackage()?;
        core.register_account_bundle()?;
        Ok(core)
    }

    /// Builds the inbox/account/MLS/causal state, subscribes both inbound
    /// addresses, and assembles the service bundle — shared by both constructors.
    fn assemble(
        ident: IP,
        identity: Identity,
        mut delivery: DS,
        registration: RS,
        wakeup_service: WS,
        store: CS,
    ) -> Result<Self, ChatError> {
        let inbox = Inbox::new(&identity);
        let ident_id = ident.id().clone();
        let mls_identity = MlsIdentityProvider::new(ident);
        let mls_provider = MlsEphemeralPqProvider::new().map_err(ChatError::generic)?;
        let causal = CausalHistoryStore::new();
        let pq_inbox = InboxV2::new(ident_id);

        // Subscribe to inbound addresses for both conversation stacks.
        delivery
            .subscribe(inbox.delivery_address())
            .map_err(ChatError::generic)?;
        delivery
            .subscribe(&pq_inbox.delivery_address())
            .map_err(ChatError::generic)?;

        Ok(Self {
            services: ServiceContext {
                ds: delivery,
                registry: registration,
                store,
                mls_identity,
                mls_provider,
                causal,
                identity,
                wakeup_service,
            },
            inbox,
            pq_inbox,
            cached_convos: HashMap::new(),
        })
    }
}

impl<'a, S: ExternalServices + 'static> Core<S> {
    pub fn ds(&mut self) -> &mut S::DS {
        &mut self.services.ds
    }

    pub fn store(&self) -> &S::CS {
        &self.services.store
    }

    pub fn identity(&self) -> &Identity {
        &self.services.identity
    }

    /// Returns the unique identifier associated with the account
    pub fn ident_id(&'a self) -> IdentIdRef<'a> {
        self.pq_inbox.ident_id()
    }

    /// Submit the local account's MLS KeyPackage to the registration service.
    /// Idempotent on the server side (registries that retain history will keep
    /// the most recent N submissions; older entries are pruned).
    pub fn register_keypackage(&mut self) -> Result<(), ChatError> {
        self.pq_inbox.register(&mut self.services)
    }

    /// Publish this installation's device key into the account → device
    /// directory, so inviters can resolve this account to its device(s). Pairs
    /// with [`register_keypackage`](Self::register_keypackage); call both after
    /// provisioning so the account is fully discoverable.
    pub fn register_account_bundle(&mut self) -> Result<(), ChatError> {
        self.pq_inbox.publish_device_bundle(&mut self.services)
    }

    pub fn installation_name(&self) -> &str {
        self.services.identity.get_name()
    }

    pub fn installation_key(&self) -> PublicKey {
        self.services.identity.public_key()
    }

    pub fn create_private_convo(
        &mut self,
        remote_bundle: &Introduction,
        content: &[u8],
    ) -> Result<ConversationId, ChatError> {
        let (mut convo, payloads) =
            self.inbox
                .invite_to_private_convo(&mut self.services, remote_bundle, content)?;

        let remote_id = Inbox::inbox_identifier_for_key(*remote_bundle.installation_key());
        let convo_id = convo.persist(&mut self.services.store)?;
        for payload in payloads {
            self.services
                .ds
                .publish(payload.into_envelope(remote_id.clone()))
                .map_err(|e| ChatError::Delivery(e.to_string()))?;
        }
        Ok(convo_id)
    }

    pub fn create_group_convo(
        &mut self,
        participants: &[IdentIdRef],
    ) -> Result<ConversationId, ChatError> {
        self.create_group_convo_v2(participants)
    }

    pub fn create_group_convo_v1(
        &mut self,
        participants: &[IdentIdRef],
    ) -> Result<ConversationId, ChatError> {
        // TODO: (P1) Ensure errors are handled properly. This is a high chance for
        // desynchronized state: MlsGroup persistence, conversation persistence, and
        // invite delivery all happen separately.
        let mut convo = GroupV1Convo::new(&mut self.services)?;
        self.services
            .store
            .save_conversation(&storage::ConversationMeta {
                local_convo_id: convo.id().to_string(),
                remote_convo_id: "0".into(),
                kind: ConversationKind::GroupV1,
            })?;
        convo.add_member(&mut self.services, participants)?;
        let convo_id = convo.id().to_string();

        self.register_convo(ConvoTypeOwned::Group(Box::new(convo)))?;

        Ok(convo_id)
    }

    pub fn create_group_convo_v2(
        &mut self,
        participants: &[IdentIdRef],
    ) -> Result<ConversationId, ChatError> {
        // TODO: (P1) Ensure errors are handled properly. This is a high chance for
        // desynchronized state: MlsGroup persistence, conversation persistence, and
        // invite delivery all happen separately.
        let mut convo = GroupV2Convo::new(&mut self.services)?;
        convo.add_member(&mut self.services, participants)?;
        let convo_id = convo.id().to_string();

        self.register_convo(ConvoTypeOwned::Group(Box::new(convo)))?;

        Ok(convo_id)
    }

    /// Add members to an existing group conversation.
    pub fn group_add_member(
        &mut self,
        convo_id: &str,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError> {
        if self.cached_convos.contains_key(convo_id) {
            let convo = self
                .cached_convos
                .get_mut(convo_id)
                .ok_or_else(|| ChatError::NoConvo(convo_id.to_string()))?;

            match convo {
                ConvoTypeOwned::Group(group_convo) => {
                    group_convo.add_member(&mut self.services, members)
                }
            }
        } else {
            let mut convo = self.load_group_convo(convo_id)?;
            convo.add_member(&mut self.services, members)
        }
    }

    pub fn list_conversations(&self) -> Result<Vec<ConversationId>, ChatError> {
        // Check Legacy load_convo store
        let records = self.services.store.load_conversations()?;
        let mut convos: Vec<ConversationId> =
            records.into_iter().map(|r| r.local_convo_id).collect();

        // Add cached mls convos
        for convo in self.cached_convos.keys() {
            convos.push(convo.to_string());
        }

        // Conversations may use both storage mechanisms.
        // Remove duplicates
        convos.dedup();
        Ok(convos)
    }

    pub fn take_missing_messages(&self) -> Vec<MissingMessage> {
        self.services.causal.take_missing()
    }

    /// Encrypt and publish `content` to an existing conversation.
    pub fn send_content(&mut self, convo_id: &str, content: &[u8]) -> Result<(), ChatError> {
        if self.cached_convos.contains_key(convo_id) {
            let convo = self
                .cached_convos
                .get_mut(convo_id)
                .ok_or_else(|| ChatError::NoConvo(convo_id.to_string()))?;
            convo.send_content(&mut self.services, content)
        } else {
            let mut convo = self.load_convo(convo_id)?;
            convo.send_content(&mut self.services, content)
        }
    }

    // Decode bytes and send to protocol for processing.
    #[instrument(name = "core.handle_frame", skip_all, fields(user_id = %self.services.mls_identity.display_name()))]
    pub fn handle_payload(&mut self, payload: &[u8]) -> Result<PayloadOutcome, ChatError> {
        let env = EnvelopeV1::decode(payload)?;

        // TODO: Impl Conversation hinting
        let convo_id = env.conversation_hint;

        match convo_id {
            c if c == self.inbox.id() => self.dispatch_to_inbox(&env.payload).map(Into::into),
            c if c == self.pq_inbox.id() => self.dispatch_to_inbox2(&env.payload),
            c if self.cached_convos.contains_key(&c) => {
                self.dispatch_to_convo(&c, &env.payload).map(Into::into)
            }
            c if self.services.store.has_conversation(&c)? => {
                self.dispatch_to_convo(&c, &env.payload).map(Into::into)
            }
            _ => Ok(PayloadOutcome::Empty),
        }
    }

    // Dispatch encrypted payload to Inbox. The Inbox persists the newly
    // created conversation and consumes the ephemeral key internally.
    fn dispatch_to_inbox(&mut self, enc_payload_bytes: &[u8]) -> Result<InboxOutcome, ChatError> {
        // EncryptedPayloads are not used by GroupConvos at this time, else this can be performed in `handle_payload`
        // TODO: (P1) reconcile envelope parsing between Covno and GroupConvo
        let enc_payload = EncryptedPayload::decode(enc_payload_bytes)?;
        let public_key_hex = Inbox::extract_ephemeral_key_hex(&enc_payload)?;
        self.inbox
            .handle_frame(&mut self.services, enc_payload, &public_key_hex)
    }

    // Dispatch encrypted payload to the post-quantum inbox.
    fn dispatch_to_inbox2(&mut self, payload: &[u8]) -> Result<PayloadOutcome, ChatError> {
        if let Some(convo) = self.pq_inbox.handle_frame(&mut self.services, payload)? {
            let convo_id = convo.id().to_string();
            // Cache convos created by InboxV2
            self.register_convo(ConvoTypeOwned::Group(convo))?;

            Ok(PayloadOutcome::Inbox(InboxOutcome {
                new_conversation: crate::NewConversation {
                    convo_id,
                    class: crate::ConversationClass::Group,
                },
                initial: None,
            }))
        } else {
            Ok(PayloadOutcome::Empty)
        }
    }

    // Dispatch encrypted payload to its corresponding conversation.
    fn dispatch_to_convo(
        &mut self,
        convo_id: &str,
        enc_payload_bytes: &[u8],
    ) -> Result<ConvoOutcome, ChatError> {
        let enc_payload = EncryptedPayload::decode(enc_payload_bytes)?;

        if self.cached_convos.contains_key(convo_id) {
            let convo_type = self
                .cached_convos
                .get_mut(convo_id)
                .ok_or_else(|| ChatError::NoConvo(convo_id.to_string()))?;

            convo_type.handle_frame(&mut self.services, enc_payload)
        } else {
            let mut convo = self.load_convo(convo_id)?;
            convo.handle_frame(&mut self.services, enc_payload)
        }
    }

    pub fn wakeup(&mut self, convo_id: ConversationIdRef) -> Result<(), ChatError> {
        info!(convos = ?self.cached_convos.keys().collect::<Vec<_>>(), id = ?self.services.mls_identity.id(), "Cached Convos");

        match convo_id {
            c if c == self.pq_inbox.id() => todo!(),
            c if self.cached_convos.contains_key(c) => self.wakeup_convo(c),
            _ => Ok(()),
        }
    }

    // Dispatch encrypted payload to its corresponding conversation
    fn wakeup_convo(&mut self, convo_id: ConversationIdRef) -> Result<(), ChatError> {
        let Some(convo) = self.cached_convos.get_mut(convo_id) else {
            return Err(ChatError::generic("No Convo Found"));
        };
        let convo = match convo {
            ConvoTypeOwned::Group(c) => c.as_mut(),
        };

        convo.wakeup(&mut self.services)
    }

    fn register_convo(&mut self, convo: ConvoTypeOwned<S>) -> Result<(), ChatError> {
        let res = self.cached_convos.insert(convo.id().to_string(), convo);

        match res {
            Some(_) => Err(ChatError::generic("Convo already exists. Cannot save")),
            None => Ok(()),
        }
    }

    /// Rebuilds a conversation from storage — the one site that branches on
    /// `ConversationKind`.
    fn load_convo(&mut self, convo_id: &str) -> Result<Box<dyn Convo<S>>, ChatError> {
        let record = self.load_conversation_meta(convo_id)?;
        Ok(match record.kind {
            ConversationKind::PrivateV1 => Box::new(PrivateV1Convo::new(
                &self.services.store,
                record.local_convo_id,
                record.remote_convo_id,
            )?),
            ConversationKind::GroupV1 => Box::new(self.load_mls_convo(&record.local_convo_id)?),
            ConversationKind::Unknown(_) => {
                return Err(ChatError::UnsupportedConvoType(record.kind.as_str().into()));
            }
        })
    }

    /// Rebuilds a group conversation; errors if `convo_id` names a non-group.
    fn load_group_convo(&mut self, convo_id: &str) -> Result<Box<dyn GroupConvo<S>>, ChatError> {
        let record = self.load_conversation_meta(convo_id)?;
        match record.kind {
            ConversationKind::GroupV1 => Ok(Box::new(self.load_mls_convo(&record.local_convo_id)?)),
            ConversationKind::PrivateV1 => {
                Err(ChatError::NoConvo("this is not a group convo".into()))
            }
            ConversationKind::Unknown(_) => {
                Err(ChatError::UnsupportedConvoType(record.kind.as_str().into()))
            }
        }
    }

    /// Rebuilds a group conversation from storage so an operation can run against it.
    fn load_mls_convo(&mut self, convo_id: &str) -> Result<GroupV1Convo, ChatError> {
        let group_id_bytes = hex::decode(convo_id).map_err(ChatError::generic)?;
        let group_id = GroupId::from_slice(&group_id_bytes);
        GroupV1Convo::load(&mut self.services, convo_id.to_string(), group_id)
    }

    pub fn create_intro_bundle(&mut self) -> Result<Vec<u8>, ChatError> {
        let intro = self.inbox.create_intro_bundle(&mut self.services)?;
        Ok(intro.into())
    }

    /// Loads a conversation's metadata from storage.
    fn load_conversation_meta(
        &self,
        convo_id: &str,
    ) -> Result<storage::ConversationMeta, ChatError> {
        self.services
            .store
            .load_conversation(convo_id)?
            .ok_or_else(|| ChatError::NoConvo(convo_id.into()))
    }
}

#[derive(Debug)]
enum ConvoTypeOwned<S: ExternalServices> {
    // Pairwise(Box<dyn BaseConvo<S>>),
    Group(Box<dyn GroupConvo<S>>),
}

impl<'a, S: ExternalServices> ConvoTypeOwned<S> {
    pub fn id(&'a self) -> ConversationIdRef<'a> {
        match self {
            ConvoTypeOwned::Group(group_convo) => group_convo.id(),
        }
    }
}

impl<S: ExternalServices> Convo<S> for ConvoTypeOwned<S> {
    fn send_content(
        &mut self,
        cx: &mut ServiceContext<S>,
        content: &[u8],
    ) -> Result<(), ChatError> {
        match self {
            ConvoTypeOwned::Group(group_convo) => group_convo.send_content(cx, content),
        }
    }

    fn handle_frame(
        &mut self,
        cx: &mut ServiceContext<S>,
        enc: EncryptedPayload,
    ) -> Result<ConvoOutcome, ChatError> {
        match self {
            ConvoTypeOwned::Group(group_convo) => group_convo.handle_frame(cx, enc),
        }
    }

    fn wakeup(&mut self, service_ctx: &mut ServiceContext<S>) -> Result<(), ChatError> {
        match self {
            ConvoTypeOwned::Group(group_convo) => group_convo.wakeup(service_ctx),
        }
    }
}
