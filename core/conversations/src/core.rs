use crate::causal_history::{CausalHistoryStore, MissingMessage};
use crate::service_context::{ExternalServices, ServiceContext};
use crate::{DeliveryService, IdentityProvider, RegistrationService};
use crate::{
    conversation::{Convo, GroupConvo, GroupV1Convo, PrivateV1Convo},
    errors::ChatError,
    inbox::Inbox,
    inbox_v2::{InboxV2, MlsEphemeralPqProvider, MlsIdentityProvider},
    outcomes::{ConvoOutcome, InboxOutcome, PayloadOutcome},
    proto::{EncryptedPayload, EnvelopeV1, Message},
};
use crypto::{Identity, PublicKey};
use openmls::prelude::GroupId;
use shared_traits::IdentIdRef;
use storage::{ChatStore, ConversationKind, ConversationStore};

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
}

// Constructors live on the `(DS, RS, CS)` form: `S` can't be inferred backwards
// through `S::DS`, so the bundle is built from the three args here.
impl<IP, DS, RS, CS> Core<(IP, DS, RS, CS)>
where
    IP: IdentityProvider + 'static,
    DS: DeliveryService + 'static,
    RS: RegistrationService + 'static,
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
        mut store: CS,
    ) -> Result<Self, ChatError> {
        let identity = if let Some(identity) = store.load_identity()? {
            identity
        } else {
            let identity = Identity::new(ident.id().as_str().to_string());
            store.save_identity(&identity)?;
            identity
        };

        Self::assemble(ident, identity, delivery, registration, store)
    }

    /// Creates a new in-memory `Core` (for testing).
    ///
    /// Uses in-memory SQLite database. Each call creates a new isolated database.
    pub fn new_with_name(
        ident: IP,
        delivery: DS,
        registration: RS,
        mut store: CS,
    ) -> Result<Self, ChatError> {
        let identity = Identity::new(ident.id().as_str().to_string());
        let mut core = Self::assemble(ident, identity, delivery, registration, store)?;

        core.register_keypackage()?;
        Ok(core)
    }

    /// Builds the inbox/account/MLS/causal state, subscribes both inbound
    /// addresses, and assembles the service bundle — shared by both constructors.
    fn assemble(
        ident: IP,
        identity: Identity,
        mut delivery: DS,
        registration: RS,
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
            },
            inbox,
            pq_inbox,
        })
    }
}

impl<S: ExternalServices + 'static> Core<S> {
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
    pub fn ident_id(&self) -> IdentIdRef {
        self.pq_inbox.ident_id()
    }

    /// Submit the local account's MLS KeyPackage to the registration service.
    /// Idempotent on the server side (registries that retain history will keep
    /// the most recent N submissions; older entries are pruned).
    pub fn register_keypackage(&mut self) -> Result<(), ChatError> {
        self.pq_inbox.register(&mut self.services)
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
        Ok(convo.id().to_string())
    }

    /// Add members to an existing group conversation.
    pub fn group_add_member(
        &mut self,
        convo_id: &str,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError> {
        let mut convo = self.load_group_convo(convo_id)?;
        convo.add_member(&mut self.services, members)
    }

    pub fn list_conversations(&self) -> Result<Vec<ConversationId>, ChatError> {
        let records = self.services.store.load_conversations()?;
        Ok(records.into_iter().map(|r| r.local_convo_id).collect())
    }

    pub fn take_missing_messages(&self) -> Vec<MissingMessage> {
        self.services.causal.take_missing()
    }

    /// Encrypt and publish `content` to an existing conversation.
    pub fn send_content(&mut self, convo_id: &str, content: &[u8]) -> Result<(), ChatError> {
        let mut convo = self.load_convo(convo_id)?;
        convo.send_content(&mut self.services, content)
    }

    // Decode bytes and send to protocol for processing.
    pub fn handle_payload(&mut self, payload: &[u8]) -> Result<PayloadOutcome, ChatError> {
        let env = EnvelopeV1::decode(payload)?;

        // TODO: Impl Conversation hinting
        let convo_id = env.conversation_hint;

        match convo_id {
            c if c == self.inbox.id() => self.dispatch_to_inbox(&env.payload).map(Into::into),
            c if c == self.pq_inbox.id() => self.dispatch_to_inbox2(&env.payload).map(Into::into),
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
    fn dispatch_to_inbox2(&mut self, payload: &[u8]) -> Result<InboxOutcome, ChatError> {
        self.pq_inbox.handle_frame(payload, &mut self.services)
    }

    // Dispatch encrypted payload to its corresponding conversation.
    fn dispatch_to_convo(
        &mut self,
        convo_id: &str,
        enc_payload_bytes: &[u8],
    ) -> Result<ConvoOutcome, ChatError> {
        let enc_payload = EncryptedPayload::decode(enc_payload_bytes)?;
        let mut convo = self.load_convo(convo_id)?;
        convo.handle_frame(&mut self.services, enc_payload)
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
