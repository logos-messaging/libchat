// This Implementation is a Quick and Dirty Integration of DeMLS into libchat.
// DeMLS and Libchat have different execution models, trait definitions and ownership/lifetimes of objects.
// The easies path is to do a Spike to see what it would take, gather the friction points and then iterate.

use crate::{ConversationId, WakeupService};
use alloy::signers::local::PrivateKeySigner;
use blake2::{Blake2b, Digest, digest::consts::U6};
use chat_proto::logoschat::encryption::{EncryptedPayload, Plaintext, encrypted_payload};
use de_mls::app::{ConsensusContext, ConversationConfig, SessionTick, User, UserPlugins};
use de_mls::core::{
    ConsensusPlugin, ConversationState, ScoringConfig, SessionEvent, StewardListConfig,
};
use de_mls::defaults::{
    DefaultConsensusPlugin, DefaultConversationPluginsFactory, MemoryDeMlsStorage, SyncEventBus,
};
use de_mls::ds::{APP_MSG_SUBTOPIC, DeliveryServiceError, InboundPacket, OutboundPacket};
use de_mls::member_id::MemberId;
use de_mls::mls_crypto::MlsCredentials;
use de_mls::protos::de_mls::messages::v1::{
    AppMessage as AppMessageProto, MemberWelcome, app_message,
};
use hashgraph_like_consensus::signing::EthereumConsensusSigner;
use hashgraph_like_consensus::storage::InMemoryConsensusStorage;
// use hashgraph_like_consensus::signing::EthereumConsensusSigner;
use shared_traits::IdentIdRef;
use prost::Message;
use rand::RngExt;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, info, instrument};

use crate::IdentId;
use crate::IdentityProvider;
use crate::conversation::ConversationIdRef;
use crate::{
    ConvoOutcome, DeliveryService, RegistrationService, conversation::ChatError,
    types::AddressedEncryptedPayload,
};

/// A trait which bundles all the external service traits into a single scope.
/// This allows for a single bound to be used internally, and cuts down on
/// the clutter
pub trait ExternalServices {
    type IP: IdentityProvider;
    type DS: DeliveryService;
    type RS: RegistrationService;
    type WS: WakeupService;
}

/// Bridges `crate::service_context::ExternalServices` (used by `Core`/`ServiceContext`)
/// into this module's `ExternalServices`, so a `crate::service_context::ServiceContext<S>`
/// can be wrapped in this module's `ServiceContext` without a separate bundle type.
impl<S: crate::service_context::ExternalServices> ExternalServices for S {
    type IP = crate::inbox_v2::MlsIdentityProvider<S::IP>;
    type DS = S::DS;
    type RS = S::RS;
    type WS = S::WS;
}

pub struct ServiceContext<'a, S: ExternalServices> {
    pub(crate) identity_provider: &'a mut S::IP,
    pub(crate) ds: &'a mut S::DS,
    pub(crate) rs: &'a mut S::RS,
    pub(crate) wakeup_service: &'a mut S::WS,
}

impl<'a, S: ExternalServices> ServiceContext<'a, S> {
    pub fn new(
        identity_provider: &'a mut S::IP,
        ds: &'a mut S::DS,
        rs: &'a mut S::RS,
        wakeup_service: &'a mut S::WS,
    ) -> Self {
        ServiceContext {
            identity_provider,
            ds,
            rs,
            wakeup_service,
        }
    }
}

pub trait BaseConvo<S: ExternalServices>: Debug {
    fn init(&self, service_ctx: &mut ServiceContext<S>) -> Result<(), ChatError>;

    fn send_content(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        content: &[u8],
    ) -> Result<(), ChatError>;

    fn handle_frame(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        enc_payload: EncryptedPayload,
    ) -> Result<Option<ConvoOutcome>, ChatError>;

    fn wakeup(&mut self, service_ctx: &mut ServiceContext<S>) -> Result<(), ChatError>;
}

pub trait BaseGroupConvo<S: ExternalServices>: BaseConvo<S> {
    fn add_member(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError>;

    fn conversation_state(&self) -> Result<ConversationState, ChatError>;
}

/// This is a Test Wrapper of Demls MemberId Trait
/// Libchat has its own trait that will need to be intergrated at somepoint.
pub struct LocalDemlsMember {
    name: String,
}

impl LocalDemlsMember {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl MemberId for LocalDemlsMember {
    fn member_id_bytes(&self) -> &[u8] {
        self.name.as_bytes()
    }

    fn member_id_display(&self) -> &str {
        &self.name
    }
}

#[derive(Debug)]
// This Maps a Demls::DeliveryService to a crate::service_traits::DeliveryService
// It works by caching outbound messages to a Vec which is eventually drained when
// The ServiceContext is available.
//
// All methods in Convo must call drain, to ensure that messages go out.
pub struct BufferDs {
    queue: Vec<OutboundPacket>,
}

impl BufferDs {
    pub fn new() -> Self {
        Self { queue: vec![] }
    }

    // Warn: Messages are not sent untill drain is called, which is after the return from User.
    // If de-mls relies on interactive sends, this will not work.
    pub fn drain<S: ExternalServices>(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<(), ChatError> {
        // Swap the Vec out; Own then existing and replace with a new empty vec.
        for pkt in self.queue.drain(..) {
            debug!(
                app = pkt.app_id.as_slice(),
                convo = pkt.conversation_id,
                topic = pkt.subtopic,
                pkt = pkt.payload.as_slice(),
                "Draining"
            );

            let hash = Blake2b::<U6>::new()
                .chain_update("delivery_addr|")
                .chain_update(&pkt.conversation_id)
                .finalize();
            let delivery_address = hex::encode(hash);
            // All Payloads leaving GroupV2 are a GroupV2Frame
            let frame = GroupV2Frame {
                payload: Some(GroupV2Payload::DeMlsWrapper(pkt.payload.into())),
                sender_app_id: pkt.app_id.clone(), // pkt.app_id is the sender's User app_id
            };

            // Wrap in EncryptedPayload
            let payload = AddressedEncryptedPayload {
                // Note: Likely a mismatch herem as de-mls is expecting a specific topic.
                delivery_address,
                data: EncryptedPayload {
                    encryption: Some(encrypted_payload::Encryption::Plaintext(Plaintext {
                        payload: frame.encode_to_vec().into(),
                    })),
                },
            };

            let env = payload.into_envelope(pkt.conversation_id.clone());

            service_ctx.ds.publish(env).map_err(ChatError::generic)?;
        }

        Ok(())
    }
}

impl de_mls::ds::DeliveryService for BufferDs {
    type Error = DeliveryServiceError;

    fn publish(&mut self, packet: de_mls::ds::OutboundPacket) -> Result<(), Self::Error> {
        info!(topic = packet.subtopic, "Publish");
        self.queue.push(packet);
        Ok(())
    }

    fn subscribe(&mut self, _delivery_address: &str) -> Result<(), Self::Error> {
        todo!()
    }
}

pub struct LibchatConsensusPlugin;

impl ConsensusPlugin for LibchatConsensusPlugin {
    type Scope = String;
    type ConsensusStorage = InMemoryConsensusStorage<String>;
    type EventBus = SyncEventBus<String>;
    type Signer = EthereumConsensusSigner;

    fn new_storage() -> Self::ConsensusStorage {
        InMemoryConsensusStorage::new()
    }

    fn new_event_bus() -> Self::EventBus {
        SyncEventBus::default()
    }
}

pub struct DeMlsV1Convo {
    convo_id: String,
    user: User<DefaultConsensusPlugin, DefaultConversationPluginsFactory>,
    // DeMLS takes shared ownership over the DS, so its incompatible with the &mut ServiceContext
    // Use a wrapper for now, and then look at refactoring.
    buffer_ds: Arc<Mutex<BufferDs>>,
    app_id: String,
}

impl std::fmt::Debug for DeMlsV1Convo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupV2Convo")
            .field("convo_id", &self.convo_id)
            .finish_non_exhaustive()
    }
}

fn rand_string(n: usize) -> String {
    rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(n)
        .map(char::from)
        .collect()
}

impl DeMlsV1Convo {
    /// Build a de-mls `User` (plugins + BufferDs transport) without starting
    /// any conversation. Shared by `new` (creator) and `new_pending` (joiner).
    pub fn build_demls(
        identity_name: String,
    ) -> Result<
        (
            User<DefaultConsensusPlugin, DefaultConversationPluginsFactory>,
            Arc<Mutex<BufferDs>>,
            String,
        ),
        ChatError,
    > {
        let identity = LocalDemlsMember::new(identity_name);
        let credentials = Arc::new(MlsCredentials::from_member_id(&identity)?);
        let storage = Arc::new(MemoryDeMlsStorage::new());
        let conversation_plugins = DefaultConversationPluginsFactory::new(storage, credentials);

        let consensus_signer = EthereumConsensusSigner::new(PrivateKeySigner::random());
        let consensus = ConsensusContext::<DefaultConsensusPlugin>::new(consensus_signer);

        // TODO(config): TEST-ONLY millisecond timers. de-mls deadlines are real
        // wall-clock, so the default 60s timers never fire under fast virtual
        // time. Production needs a real config injected from the caller, not
        // these hardcoded values.
        let conversation_config = ConversationConfig {
            commit_inactivity_duration: Duration::from_millis(50),
            freeze_duration: Duration::from_millis(20),
            voting_delay: Duration::from_millis(30),
            election_voting_delay: Duration::from_millis(30),
            consensus_timeout: Duration::from_millis(150),
            proposal_expiration: Duration::from_millis(2000),
            ..ConversationConfig::default()
        };

        let plugins = UserPlugins {
            conversation_plugins,
            consensus,
            default_conversation_config: conversation_config,
            default_scoring_config: ScoringConfig::default(),
            default_steward_list_config: StewardListConfig::default(),
        };

        let transport = Arc::new(Mutex::new(BufferDs::new()));
        let user = User::new_with_plugins(Box::new(identity), plugins, transport.clone());
        Ok((user, transport, rand_string(5)))
    }

    pub fn new<S: ExternalServices>(
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<Self, ChatError> {
        let convo_id = rand_string(5);
        let identity_name = service_ctx.identity_provider.display_name();
        let (mut user, transport, app_id) = Self::build_demls(identity_name)?;

        user.start_conversation(convo_id.as_str(), true)?;

        // Ensure that the BufferDs gets drained
        transport.lock().unwrap().drain(service_ctx)?;

        Ok(Self {
            convo_id,
            user,
            buffer_ds: transport,
            app_id,
        })
    }

    /// Joiner side: build a de-mls `User` and register its key package under
    /// the account name, but do NOT start a conversation. `convo_id` stays
    /// empty until [`Self::accept_welcome`] fills it.
    pub fn new_pending<S: ExternalServices>(
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<Self, ChatError> {
        let name = service_ctx.identity_provider.display_name();
        let (user, transport, app_id) = Self::build_demls(name.clone())?;

        // let kp = user.generate_key_package()?;
        // let key = format!("demls:{}", service_ctx.identity_provider.id().as_str());

        // Inbox handles registration
        // service_ctx
        //     .rs
        //     .register(&key, service_ctx.identity_provider, kp.as_bytes().to_vec())
        //     .map_err(ChatError::generic)?;

        Ok(Self {
            convo_id: String::new(),
            user,
            buffer_ds: transport,
            app_id,
        })
    }

    /// Joiner side: ingest a de-mls welcome handed over the InboxV2 1-1
    /// channel. Attaches MLS (filling `convo_id`), replays the bundled
    /// `ConversationSync`, then subscribes to the conversation address.
    pub fn accept_welcome<
        S: ExternalServices,
        IP: IdentityProvider,
        DS: DeliveryService,
        WS: WakeupService,
    >(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        welcome: &MemberWelcome,
    ) -> Result<(), ChatError> {
        let (convo_id, tick) = self.user.accept_welcome(&welcome.welcome_bytes)?;
        self.convo_id = convo_id;

        if !welcome.conversation_sync_bytes.is_empty() {
            let pkt = InboundPacket::new(
                welcome.conversation_sync_bytes.clone(),
                APP_MSG_SUBTOPIC,
                &self.convo_id,
                self.user.app_id().to_vec(),
                0,
            );
            self.user.process_inbound_packet(pkt)?;
        }

        let events = self.user.drain_events(&self.convo_id)?;
        self.init(service_ctx)?;
        self.after_op(service_ctx, tick, &events)
    }

    fn id(&self) -> ConversationIdRef<'_> {
        &self.convo_id
    }

    fn delivery_address_from_id(convo_id: &str) -> String {
        let hash = Blake2b::<U6>::new()
            .chain_update("delivery_addr|")
            .chain_update(convo_id)
            .finalize();
        hex::encode(hash)
    }

    #[allow(unused)]
    fn delivery_address(&self) -> String {
        Self::delivery_address_from_id(&self.convo_id)
    }

    fn ctrl_delivery_address_from_id(convo_id: &str) -> String {
        Self::delivery_address_from_id(convo_id)
    }
    #[allow(unused)]
    fn ctrl_delivery_address(&self) -> String {
        Self::ctrl_delivery_address_from_id(&self.convo_id)
    }

    // Needed by Demls
    fn app_id(&self) -> &str {
        &self.app_id
    }

    pub fn convo_id(&self) -> ConversationIdRef {
        &self.convo_id
    }
}

impl<S: ExternalServices> BaseConvo<S> for DeMlsV1Convo {
    fn init(&self, service_ctx: &mut ServiceContext<S>) -> Result<(), ChatError> {
        // Configure the delivery service to listen for the required delivery addresses.

        service_ctx
            .ds
            .subscribe(&Self::delivery_address_from_id(&self.convo_id))
            .map_err(ChatError::generic)?;
        service_ctx
            .ds
            .subscribe(&Self::ctrl_delivery_address_from_id(&self.convo_id))
            .map_err(ChatError::generic)?;

        // Ensure that the BufferDs gets drained
        self.buffer_ds.lock().unwrap().drain(service_ctx)?;
        Ok(())
    }

    #[instrument(name = "groupv2.send_content", skip_all, fields(user_id = %service_ctx.identity_provider.display_name(), content))]
    fn send_content(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        content: &[u8],
    ) -> Result<(), ChatError> {
        let tick = self
            .user
            .send_app_message(&self.convo_id, content.to_vec())?;
        // Ensure that the BufferDs gets drained - done inside after_op
        self.after_op(service_ctx, tick, &vec![])?;
        Ok(())
    }

    #[instrument(name = "groupv2.handle_frame", skip_all, fields(user_id = %service_ctx.identity_provider.display_name()))]
    fn handle_frame(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        encoded_payload: EncryptedPayload,
    ) -> Result<Option<ConvoOutcome>, ChatError> {
        let bytes = match encoded_payload.encryption {
            Some(encrypted_payload::Encryption::Plaintext(pt)) => pt.payload,
            _ => {
                return Err(ChatError::generic("Expected plaintext"));
            }
        };
        let frame = GroupV2Frame::decode(bytes.as_ref()).map_err(ChatError::generic)?;
        let inner = match frame.payload {
            Some(GroupV2Payload::DeMlsWrapper(b)) => b.to_vec(),
            _ => return Ok(None),
        };

        // Fake a InboundPacket
        let packet = InboundPacket {
            payload: inner,
            subtopic: APP_MSG_SUBTOPIC.to_string(), // Assume APP TOPIC, Welcome Messages go to InboxV2
            conversation_id: self.convo_id.to_string(),
            app_id: frame.sender_app_id,
            timestamp: 0,
        };

        info!(len = packet.payload.len(), "Inbound Pkt");
        let tick = self.user.process_inbound_packet(packet)?;
        let events = self.user.drain_events(&self.convo_id)?;
        let out = self.events_to_content(events.clone());
        self.after_op(service_ctx, tick, &events)?;
        Ok(out)
    }

    #[instrument(name = "groupv2.wakeup", skip_all, fields(user_id = %ctx.identity_provider.display_name()))]
    fn wakeup(&mut self, ctx: &mut ServiceContext<S>) -> Result<(), ChatError> {
        info!(app = self.app_id(), "Wakeup");
        let tick = self.user.poll_session(&self.convo_id)?;
        let events = self.user.drain_events(&self.convo_id)?;
        self.after_op(ctx, tick, &events)
    }
}

impl<S> BaseGroupConvo<S> for DeMlsV1Convo
where
    S: ExternalServices,
{
    #[instrument(name = "groupv2.add_member", skip_all, fields(user_id = %service_ctx.identity_provider.display_name()))]
    fn add_member(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError> {
        let mut last_tick = SessionTick {
            next_wakeup_in: None,
        };
        for member in members {
            let demls_key = format!("demls:{}", member.as_str());
            let kp_bytes = service_ctx
                .rs
                .retrieve(&demls_key)
                .map_err(ChatError::generic)?
                .ok_or_else(|| ChatError::generic("No key package"))?;
            last_tick = self.user.add_member(&self.convo_id, &kp_bytes)?;
        }
        let events = self.user.drain_events(&self.convo_id)?;
        self.after_op(service_ctx, last_tick, &events)
    }

    fn conversation_state(&self) -> Result<ConversationState, ChatError> {
        self.user
            .get_conversation_state(&self.convo_id)
            .map_err(ChatError::DeMlsGeneric)
    }
}

impl DeMlsV1Convo {
    fn after_op<S: ExternalServices>(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        tick: SessionTick,
        events: &[SessionEvent],
    ) -> Result<(), ChatError> {
        // Route each welcome to the joiners it names over their InboxV2 1-1
        // channel. The welcome carries `joiner_identities` (member-id bytes =
        // account name), so any node that commits an Add can address delivery
        // — no local invite tracking, and batch Adds route correctly.
        for evt in events {
            if let SessionEvent::WelcomeReady(welcome) = evt {
                for joiner in &welcome.joiner_identities {
                    let name = String::from_utf8(joiner.clone()).map_err(ChatError::generic)?;
                    let account = IdentId::new(name);
                    crate::inbox_v2::invite_user_v2(service_ctx.ds, &account, welcome)?;
                }
            }
        }

        self.buffer_ds.lock().unwrap().drain(service_ctx)?;
        if let Some(d) = tick.next_wakeup_in {
            // TODO(chat): WakeupService is second-granularity but de-mls
            // deadlines are sub-second; `as_secs().max(1)` floors them up to 1s,
            // silently over-waiting. Needs a millisecond-capable wakeup.
            service_ctx
                .wakeup_service
                .wakeup_in(d, self.convo_id.clone());
        }
        Ok(())
    }

    fn events_to_content(&mut self, events: Vec<SessionEvent>) -> Option<ConvoOutcome> {
        let mut latest: Option<ConvoOutcome> = None;

        for evt in events {
            match evt {
                SessionEvent::AppMessage(AppMessageProto { payload: Some(p) }) => match p {
                    app_message::Payload::ConversationMessage(cm) => {
                        latest = Some(ConvoOutcome {
                            convo_id: self.convo_id.clone(),
                            content: Some(crate::Content { bytes: cm.message }),
                        });
                    }
                    // All other types is an inside group traffic — not chat content.
                    _ => {}
                },
                _ => {}
            }
        }

        latest
    }
}

use prost::{Oneof, bytes::Bytes};

#[derive(Clone, PartialEq, Message)]
pub struct GroupV2Frame {
    #[prost(oneof = "GroupV2Payload", tags = "2, 3")]
    pub payload: Option<GroupV2Payload>,
    #[prost(bytes = "vec", tag = "4")]
    pub sender_app_id: Vec<u8>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum GroupV2Payload {
    #[prost(message, tag = "2")]
    DeMlsWrapper(Bytes),
    #[prost(message, tag = "3")]
    MlsCommitMessage(Bytes),
}
