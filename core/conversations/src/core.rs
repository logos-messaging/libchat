use crate::Protocol;
use crate::causal_history::{CausalHistoryStore, DeliveryAck, MissingMessage};
use crate::conversation::{
    ConversationIdRef, ConvoTypeOwned, DirectV1Convo, GroupV1Convo, GroupV2Convo, Identified,
    MessageId,
};
use crate::service_context::{ExternalServices, ServiceContext};
use crate::staged_delivery::StagedDelivery;
use crate::types::ConvoMetadata;
use crate::{
    DeliveryService, GroupV2Clock, GroupV2Config, IdentityProvider, RegistrationService,
    WakeupService,
};
use crate::{
    conversation::{Convo, GroupConvo},
    errors::ChatError,
    inbox_v2::{InboxV2, Joined, MlsIdentityProvider},
    outcomes::{ConvoOutcome, InboxOutcome, PayloadOutcome},
    proto::{EncryptedPayload, EnvelopeV1, Message},
};
use crypto::{Identity, PublicKey};
use openmls_libcrux_crypto::CryptoProvider as LibcruxCryptoProvider;
use shared_traits::{IdentId, IdentIdRef};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use storage::{
    ConversationKind, ConversationMeta, ConversationStore, KvTransaction, Scope, ScopedKvStore,
    Store,
};
use tracing::{info, instrument};

pub use crate::conversation::ConversationId;

// This is the main entry point to the conversations api.
// `Core` manages lifetimes of objects to process and generate payloads.
//
// Fully synchronous and single-threaded: it owns its services outright (no
// interior mutability, no shared ownership) and drives the inbox/conversation
// primitives with plain `&mut self`.
pub struct Core<S: ExternalServices> {
    store: S::CS,
    services: ServiceContext<S>,
    pq_inbox: InboxV2,
    // Cache of loaded conversations
    cached_convos: HashMap<String, ScopedConvo<S>>,
}

// Constructors live on the `(DS, RS, CS)` form: `S` can't be inferred backwards
// through `S::DS`, so the bundle is built from the three args here.
impl<IP, DS, RS, WS, CS> Core<(IP, DS, RS, WS, CS)>
where
    IP: IdentityProvider + 'static,
    DS: DeliveryService + 'static,
    RS: RegistrationService + 'static,
    WS: WakeupService + 'static,
    CS: Store + 'static,
{
    /// Opens or creates a `Core` over the given store.
    ///
    /// The identity is restored when the store holds one, and created and saved when it does not.
    /// Conversations are rebuilt from the store before this installation's key package is
    /// published.
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

        let mut core = Self::assemble(
            ident,
            identity,
            delivery,
            registration,
            wakeup_service,
            store,
        )?;

        core.hydrate()?;
        core.register_keypackage()?;
        Ok(core)
    }

    pub fn set_group_v2_clock(&mut self, clock: GroupV2Clock) {
        self.services.demls_clock = clock;
    }

    /// Overrides the GroupV2 (de-mls) timing/policy config. Applies to
    /// conversations created/joined after the call; a creator's phase
    /// durations reach joiners inside the welcome's `ConversationSync`.
    pub fn set_group_v2_config(&mut self, config: GroupV2Config) {
        self.services.demls_config = config;
    }

    /// Builds the inbox/account/MLS/causal state, subscribes both inbound
    /// addresses, and assembles the service bundle.
    fn assemble(
        ident: IP,
        identity: Identity,
        mut delivery: DS,
        registration: RS,
        wakeup_service: WS,
        store: CS,
    ) -> Result<Self, ChatError> {
        // InboxV2 rendezvous is signer-scoped: it subscribes under the hex of
        // the signer's verifying key — the same string the account → device
        // directory lists and the registries key key-packages under, so it is
        // exactly what an inviter can derive for this installation. The MLS
        // credential below still carries the full `id()`.
        let ident_id = IdentId::new(hex::encode(ident.public_key().as_ref()));
        let mls_identity = MlsIdentityProvider::new(ident);
        let crypto = LibcruxCryptoProvider::new().map_err(ChatError::generic)?;
        let causal = CausalHistoryStore::new();
        let pq_inbox = InboxV2::new(ident_id);

        // Subscribe to the InboxV2 rendezvous address.
        delivery
            .subscribe(&pq_inbox.delivery_address())
            .map_err(ChatError::generic)?;

        Ok(Self {
            store,
            services: ServiceContext {
                ds: StagedDelivery::new(delivery),
                registry: registration,
                mls_identity,
                crypto,
                causal,
                identity,
                wakeup_service,
                demls_clock: GroupV2Clock::default(),
                demls_config: GroupV2Config::default(),
            },
            pq_inbox,
            cached_convos: HashMap::new(),
        })
    }

    /// Rebuilds the conversations the store lists, which also restores the delivery subscription
    /// each one holds. A record whose kind has no load path stays in the store and reports
    /// `UnsupportedConvoType` the next time it is addressed.
    fn hydrate(&mut self) -> Result<(), ChatError> {
        let records = self.store.load_conversations()?;
        let tx = KvTransaction::begin(&self.store)?;
        for record in records {
            match Self::build_convo(&mut self.services, &tx, &record) {
                Ok(scoped) => {
                    self.cached_convos.insert(record.local_convo_id, scoped);
                }
                Err(ChatError::UnsupportedConvoType(_)) => continue,
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }
}

impl<'a, S: ExternalServices + 'static> Core<S> {
    pub fn ds(&mut self) -> &mut S::DS {
        self.services.ds.inner_mut()
    }

    pub fn store(&self) -> &S::CS {
        &self.store
    }

    pub fn identity(&self) -> &Identity {
        &self.services.identity
    }

    /// The signer id this core receives InboxV2 invites under — the hex of the
    /// signer's verifying key.
    pub fn ident_id(&'a self) -> IdentIdRef<'a> {
        self.pq_inbox.ident_id()
    }

    /// Submit the local account's MLS KeyPackage to the registration service.
    /// Idempotent on the server side (registries that retain history will keep
    /// the most recent N submissions; older entries are pruned).
    ///
    /// Submitted only once the transaction holding its private keys has landed, so the registry
    /// never serves a package whose welcome this installation could not open.
    pub fn register_keypackage(&mut self) -> Result<(), ChatError> {
        let tx = KvTransaction::begin(&self.store)?;
        let minted = self.pq_inbox.register(&mut self.services, &tx);
        let key_package = Self::commit(&mut self.services, tx, minted)?;
        self.services
            .registry
            .register(&self.services.mls_identity, key_package)
            .map_err(ChatError::generic)
    }

    pub fn installation_name(&self) -> &str {
        self.services.identity.get_name()
    }

    pub fn installation_key(&self) -> PublicKey {
        self.services.identity.public_key()
    }

    pub fn create_direct_convo(
        &mut self,
        members: &[IdentIdRef],
    ) -> Result<ConversationId, ChatError> {
        self.create_direct_convo_v1(members)
    }

    pub fn create_direct_convo_v1(
        &mut self,
        members: &[IdentIdRef],
    ) -> Result<ConversationId, ChatError> {
        let convo_id = DirectV1Convo::mint_id(&self.services.crypto);

        let tx = KvTransaction::begin(&self.store)?;
        let created = DirectV1Convo::new(
            &mut self.services,
            tx.scope(Protocol::DirectV1, Some(&convo_id)),
            convo_id.clone(),
            members,
        );
        let convo = Self::commit(&mut self.services, tx, created)?;
        self.register_convo(Protocol::DirectV1, ConvoTypeOwned::Direct(Box::new(convo)))?;
        self.save_record(&ConversationMeta {
            local_convo_id: convo_id.clone(),
            kind: ConversationKind::DirectV1,
        })?;
        self.publish()?;

        Ok(convo_id)
    }

    pub fn create_group_convo(
        &mut self,
        participants: &[IdentIdRef],
    ) -> Result<ConversationId, ChatError> {
        self.create_group_convo_v2(participants, "", "")
    }

    pub fn create_group_convo_v1(
        &mut self,
        participants: &[IdentIdRef],
    ) -> Result<ConversationId, ChatError> {
        let convo_id = GroupV1Convo::mint_id(&self.services.crypto);

        let tx = KvTransaction::begin(&self.store)?;
        let created = Self::build_group_v1(
            &mut self.services,
            tx.scope(Protocol::GroupV1, Some(&convo_id)),
            convo_id.clone(),
            participants,
        );
        let convo = Self::commit(&mut self.services, tx, created)?;
        self.register_convo(Protocol::GroupV1, ConvoTypeOwned::Group(Box::new(convo)))?;
        self.save_record(&ConversationMeta {
            local_convo_id: convo_id.clone(),
            kind: ConversationKind::GroupV1,
        })?;
        self.publish()?;

        Ok(convo_id)
    }

    pub fn create_group_convo_v2(
        &mut self,
        participants: &[IdentIdRef],
        name: &str,
        desc: &str,
    ) -> Result<ConversationId, ChatError> {
        let convo_id = GroupV2Convo::mint_id();

        let tx = KvTransaction::begin(&self.store)?;
        let created = GroupV2Convo::new(
            &mut self.services,
            tx.scope(Protocol::GroupV2, Some(&convo_id)),
            convo_id.clone(),
            name,
            desc,
            participants,
        );
        let convo = Self::commit(&mut self.services, tx, created)?;
        self.register_convo(Protocol::GroupV2, ConvoTypeOwned::Group(Box::new(convo)))?;
        self.save_record(&ConversationMeta {
            local_convo_id: convo_id.clone(),
            kind: ConversationKind::GroupV2,
        })?;
        self.publish()?;

        Ok(convo_id)
    }

    /// Add members to an existing group conversation.
    pub fn group_add_member(
        &mut self,
        convo_id: &str,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError> {
        let tx = KvTransaction::begin(&self.store)?;
        let scoped = Self::cached_or_loaded(
            &mut self.cached_convos,
            &mut self.services,
            &self.store,
            &tx,
            convo_id,
        )?;

        // A conversation with no member list is turned away before the transaction stages
        // anything, so the call costs it neither a rollback nor its place in the cache.
        let protocol = scoped.protocol;
        let ConvoTypeOwned::Group(group_convo) = &mut scoped.convo else {
            return Err(ChatError::UnsupportedFunction(
                convo_id.into(),
                "Add Member".into(),
            ));
        };

        let kv = tx.scope(protocol, Some(convo_id));
        let added = group_convo.add_member(&mut self.services, kv, members);
        let committed = Self::commit(&mut self.services, tx, added);
        self.evict_on_error(convo_id, committed)?;
        self.publish()
    }

    /// Each member's MLS leaf-credential content (hex-encoded), for a direct
    /// conversation as for a group.
    pub fn group_members(&mut self, convo_id: &str) -> Result<Vec<Vec<u8>>, ChatError> {
        let tx = KvTransaction::begin(&self.store)?;
        let scoped = Self::cached_or_loaded(
            &mut self.cached_convos,
            &mut self.services,
            &self.store,
            &tx,
            convo_id,
        )?;

        scoped.convo.members()
    }

    /// Each member invited here and still awaiting the group's commit, in the
    /// same encoding as [`Self::group_members`]. A direct conversation has no
    /// pending members and reports none.
    pub fn group_pending_members(&mut self, convo_id: &str) -> Result<Vec<Vec<u8>>, ChatError> {
        let tx = KvTransaction::begin(&self.store)?;
        let scoped = Self::cached_or_loaded(
            &mut self.cached_convos,
            &mut self.services,
            &self.store,
            &tx,
            convo_id,
        )?;

        match &scoped.convo {
            ConvoTypeOwned::Group(group_convo) => group_convo.pending_members(),
            ConvoTypeOwned::Direct(_) => Ok(Vec::new()),
        }
    }

    pub fn list_conversations(&self) -> Result<Vec<ConversationId>, ChatError> {
        // Check Legacy load_convo store
        let records = self.store.load_conversations()?;
        let mut convos: Vec<ConversationId> =
            records.into_iter().map(|r| r.local_convo_id).collect();

        // Add cached mls convos
        for convo in self.cached_convos.keys() {
            convos.push(convo.to_string());
        }

        // A conversation can live in both the store and the in-memory cache (a
        // DirectV1 join persists to the store and is also cached), so drop
        // duplicates across the two. `Vec::dedup` only removes *consecutive*
        // repeats and `cached_convos` iterates in nondeterministic HashMap
        // order, so dedup through a set instead.
        let mut seen = std::collections::HashSet::new();
        convos.retain(|c| seen.insert(c.clone()));
        Ok(convos)
    }

    /// Removes a conversation: everything its scope holds, and the record listing it.
    pub fn remove_conversation(&mut self, convo_id: &str) -> Result<(), ChatError> {
        let record = Self::load_conversation_meta(&self.store, convo_id)?;
        let scope = Scope {
            ns: Protocol::try_from(&record.kind)?.into(),
            instance: Some(convo_id),
        };
        // The record goes first: a crash between the two leaves state no record names, which a
        // purge can sweep, where the reverse order leaves a record whose scope is empty and no
        // conversation can be rebuilt from. The cache goes last, so a removal that fails leaves
        // the conversation as usable as the store still says it is.
        self.store.remove_conversation(convo_id)?;

        let tx = KvTransaction::begin(&self.store)?;
        tx.delete_scope(&scope)?;
        tx.commit()?;

        self.cached_convos.remove(convo_id);
        Ok(())
    }

    pub fn take_missing_messages(&self) -> Vec<MissingMessage> {
        self.services.causal.take_missing()
    }

    /// Drain the acknowledgements observed since the last call: peers that
    /// referenced one of our messages, and so demonstrably hold it.
    pub fn take_acks(&self) -> Vec<DeliveryAck> {
        self.services.causal.take_acks()
    }

    /// Encrypt and publish `content` to an existing conversation, returning the
    /// id assigned to the message so later acknowledgements can be matched to
    /// it.
    pub fn send_content(&mut self, convo_id: &str, content: &[u8]) -> Result<MessageId, ChatError> {
        let tx = KvTransaction::begin(&self.store)?;
        let scoped = Self::cached_or_loaded(
            &mut self.cached_convos,
            &mut self.services,
            &self.store,
            &tx,
            convo_id,
        )?;

        let kv = tx.scope(scoped.protocol, Some(convo_id));
        let sent = scoped.convo.send_content(&mut self.services, kv, content);
        let committed = Self::commit(&mut self.services, tx, sent);
        let message_id = self.evict_on_error(convo_id, committed)?;
        self.publish()?;

        Ok(message_id)
    }

    // Decode bytes and send to protocol for processing.
    #[instrument(name = "core.handle_frame", skip_all, fields(user_id = %self.services.mls_identity.display_name()))]
    pub fn handle_payload(&mut self, payload: &[u8]) -> Result<PayloadOutcome, ChatError> {
        let env = EnvelopeV1::decode(payload)?;

        // TODO: Impl Conversation hinting
        let convo_id = env.conversation_hint;

        match convo_id {
            c if c == self.pq_inbox.id() => self.dispatch_to_inbox2(&env.payload),
            c if self.cached_convos.contains_key(&c) => {
                self.dispatch_to_convo(&c, &env.payload).map(Into::into)
            }
            c if self.store.has_conversation(&c)? => {
                self.dispatch_to_convo(&c, &env.payload).map(Into::into)
            }
            _ => Ok(PayloadOutcome::Empty),
        }
    }

    // Dispatch encrypted payload to the post-quantum inbox.
    fn dispatch_to_inbox2(&mut self, payload: &[u8]) -> Result<PayloadOutcome, ChatError> {
        let tx = KvTransaction::begin(&self.store)?;
        let handled = self.pq_inbox.handle_frame(&mut self.services, &tx, payload);
        let Some(Joined { convo, record }) = Self::commit(&mut self.services, tx, handled)? else {
            return Ok(PayloadOutcome::Empty);
        };

        let convo_id = convo.id().to_string();
        let class = convo.class();
        // Cache convos created by InboxV2
        self.register_convo(Protocol::try_from(&record.kind)?, convo)?;

        self.save_record(&record)?;
        self.publish()?;

        Ok(PayloadOutcome::Inbox(InboxOutcome {
            new_conversation: crate::NewConversation { convo_id, class },
            initial: None,
        }))
    }

    // Dispatch encrypted payload to its corresponding conversation.
    fn dispatch_to_convo(
        &mut self,
        convo_id: &str,
        enc_payload_bytes: &[u8],
    ) -> Result<ConvoOutcome, ChatError> {
        let enc_payload = EncryptedPayload::decode(enc_payload_bytes)?;

        let tx = KvTransaction::begin(&self.store)?;
        let scoped = Self::cached_or_loaded(
            &mut self.cached_convos,
            &mut self.services,
            &self.store,
            &tx,
            convo_id,
        )?;

        let kv = tx.scope(scoped.protocol, Some(convo_id));
        let handled = scoped
            .convo
            .handle_frame(&mut self.services, kv, enc_payload);
        let committed = Self::commit(&mut self.services, tx, handled);
        let outcome = self.evict_on_error(convo_id, committed)?;
        self.publish()?;

        Ok(outcome)
    }

    pub fn wakeup(&mut self, convo_id: ConversationIdRef) -> Result<PayloadOutcome, ChatError> {
        info!(convos = ?self.cached_convos.keys().collect::<Vec<_>>(), id = ?self.services.mls_identity.id(), "Cached Convos");

        match convo_id {
            c if c == self.pq_inbox.id() => todo!(),
            c if self.cached_convos.contains_key(c) => self.wakeup_convo(c).map(Into::into),
            _ => Ok(PayloadOutcome::Empty),
        }
    }

    // Dispatch encrypted payload to its corresponding conversation
    fn wakeup_convo(&mut self, convo_id: ConversationIdRef) -> Result<ConvoOutcome, ChatError> {
        let Some(scoped) = self.cached_convos.get_mut(convo_id) else {
            return Err(ChatError::generic("No Convo Found"));
        };

        let tx = KvTransaction::begin(&self.store)?;
        let kv = tx.scope(scoped.protocol, Some(convo_id));
        let woken = scoped.convo.wakeup(&mut self.services, kv);
        let committed = Self::commit(&mut self.services, tx, woken);
        let outcome = self.evict_on_error(convo_id, committed)?;
        self.publish()?;

        Ok(outcome)
    }

    /// A GroupV1 create in one transaction: the group, then the invites its participants need.
    fn build_group_v1(
        cx: &mut ServiceContext<S>,
        kv: ScopedKvStore<'_>,
        convo_id: ConversationId,
        participants: &[IdentIdRef],
    ) -> Result<GroupV1Convo, ChatError> {
        let mut convo = GroupV1Convo::new(cx, kv, convo_id)?;
        convo.add_member(cx, kv, participants)?;
        Ok(convo)
    }

    /// Lands the operation's transaction. A failure discards the transaction and the frames the
    /// operation staged alike: nothing is announced that the store did not keep.
    fn commit<T>(
        cx: &mut ServiceContext<S>,
        tx: KvTransaction<'_>,
        outcome: Result<T, ChatError>,
    ) -> Result<T, ChatError> {
        let outcome = outcome.and_then(|value| {
            tx.commit()?;
            Ok(value)
        });
        if outcome.is_err() {
            cx.ds.discard();
        }
        outcome
    }

    /// Publishes what the operation staged, now that the state behind it has landed.
    fn publish(&mut self) -> Result<(), ChatError> {
        self.services
            .ds
            .flush()
            .map_err(|e| ChatError::Delivery(e.to_string()))
    }

    /// Records a conversation, dropping what is still staged if the record cannot be written: a
    /// conversation the store does not list must not have announced itself.
    fn save_record(&mut self, record: &ConversationMeta) -> Result<(), ChatError> {
        if let Err(err) = self.store.save_conversation(record) {
            self.services.ds.discard();
            return Err(err.into());
        }
        Ok(())
    }

    /// Drops the conversation a failed operation touched, so the next call rebuilds it from the
    /// state the store kept: what the operation ran in memory is a step ahead of what landed.
    ///
    /// A GroupV2 conversation cannot be rebuilt yet (#135), so it stays cached and keeps that
    /// step of lead over the store.
    fn evict_on_error<T>(
        &mut self,
        convo_id: &str,
        outcome: Result<T, ChatError>,
    ) -> Result<T, ChatError> {
        if outcome.is_err()
            && self
                .cached_convos
                .get(convo_id)
                .is_some_and(|scoped| scoped.protocol != Protocol::GroupV2)
        {
            self.cached_convos.remove(convo_id);
        }
        outcome
    }

    /// Caches a conversation under the protocol whose scope holds its state. The core does this
    /// as soon as the transaction creating it commits, since the commit is what makes it real: a
    /// record or a publish that fails afterwards must not cost it its place in memory.
    fn register_convo(
        &mut self,
        protocol: Protocol,
        convo: ConvoTypeOwned<S>,
    ) -> Result<(), ChatError> {
        let scoped = ScopedConvo { protocol, convo };
        let res = self
            .cached_convos
            .insert(scoped.convo.id().to_string(), scoped);

        match res {
            Some(_) => Err(ChatError::generic("Convo already exists. Cannot save")),
            None => Ok(()),
        }
    }

    /// The conversation an operation addresses, rebuilt from the store when the cache does not
    /// hold it and cached again, so a conversation a failed operation dropped costs one rebuild
    /// rather than every call that follows.
    fn cached_or_loaded<'c>(
        cached_convos: &'c mut HashMap<String, ScopedConvo<S>>,
        cx: &mut ServiceContext<S>,
        store: &S::CS,
        tx: &KvTransaction<'_>,
        convo_id: &str,
    ) -> Result<&'c mut ScopedConvo<S>, ChatError> {
        match cached_convos.entry(convo_id.to_string()) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => Ok(entry.insert(Self::load_convo(cx, store, tx, convo_id)?)),
        }
    }

    /// Rebuilds a conversation from storage so an operation can run against it.
    fn load_convo(
        cx: &mut ServiceContext<S>,
        store: &S::CS,
        tx: &KvTransaction<'_>,
        convo_id: &str,
    ) -> Result<ScopedConvo<S>, ChatError> {
        let record = Self::load_conversation_meta(store, convo_id)?;
        Self::build_convo(cx, tx, &record)
    }

    /// Rebuilds a conversation from its record, the one site that turns a stored
    /// `ConversationKind` into its conversation type.
    fn build_convo(
        cx: &mut ServiceContext<S>,
        tx: &KvTransaction<'_>,
        record: &ConversationMeta,
    ) -> Result<ScopedConvo<S>, ChatError> {
        let protocol = Protocol::try_from(&record.kind)?;
        let convo_id = record.local_convo_id.as_str();
        let kv = tx.scope(protocol, Some(convo_id));
        let convo = match record.kind {
            ConversationKind::GroupV1 => {
                ConvoTypeOwned::Group(Box::new(GroupV1Convo::load(cx, kv, convo_id.to_string())?))
            }
            ConversationKind::DirectV1 => {
                ConvoTypeOwned::Direct(Box::new(DirectV1Convo::load(cx, kv, convo_id.to_string())?))
            }
            // GroupV2 state is durable, but de-mls offers no way to resume a conversation from
            // it yet (#135).
            ConversationKind::GroupV2 | ConversationKind::Unknown(_) => {
                return Err(ChatError::UnsupportedConvoType(record.kind.as_str().into()));
            }
        };
        Ok(ScopedConvo { protocol, convo })
    }

    /// Loads a conversation's metadata from storage.
    fn load_conversation_meta(
        store: &S::CS,
        convo_id: &str,
    ) -> Result<storage::ConversationMeta, ChatError> {
        store
            .load_conversation(convo_id)?
            .ok_or_else(|| ChatError::NoConvo(convo_id.into()))
    }

    pub fn convo_metadata(
        &mut self,
        convo_id: ConversationIdRef,
    ) -> Result<ConvoMetadata, ChatError> {
        let tx = KvTransaction::begin(&self.store)?;
        let scoped = Self::cached_or_loaded(
            &mut self.cached_convos,
            &mut self.services,
            &self.store,
            &tx,
            convo_id,
        )?;

        match &scoped.convo {
            ConvoTypeOwned::Group(group_convo) => {
                group_convo
                    .metadata()
                    .ok_or(ChatError::UnsupportedConvoType(
                        "metadata is not available for this legacy convo_type".into(),
                    ))
            }
            ConvoTypeOwned::Direct(_) => Err(ChatError::UnsupportedFunction(
                convo_id.into(),
                "implementation coming".into(),
            )),
        }
    }
}

/// A conversation and the protocol whose scope holds its state.
struct ScopedConvo<S: ExternalServices> {
    protocol: Protocol,
    convo: ConvoTypeOwned<S>,
}
