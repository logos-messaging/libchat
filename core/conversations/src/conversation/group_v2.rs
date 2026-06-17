// This Implementation is a Quick and Dirty Integration of DeMLS into libchat.
// DeMLS and Libchat have different execution models, trait definitions and ownership/lifetimes of objects.
// The easies path is to do a Spike to see what it would take, gather the friction points and then iterate.

use crate::types::AddressedEncryptedPayload;
use crate::{Content, WakeupService};
use alloy::signers::local::PrivateKeySigner;
use blake2::{Blake2b, Digest, digest::consts::U6};
use chat_proto::logoschat::encryption::{EncryptedPayload, Plaintext, encrypted_payload};
use de_mls::core::{
    ConsensusPlugin, ConsensusServiceFor, ConversationEvent, ConversationPluginsFactory,
    DeterministicStewardList, PeerScoringService, ScoringConfig, StewardListConfig,
    default_score_deltas,
};
use de_mls::defaults::{
    DefaultConsensusPlugin, DefaultPeerScoring, DefaultStewardList, InMemoryPeerScoreStorage,
};
use de_mls::member_id::MemberId;
use de_mls::mls_crypto::{KeyPackageBytes, MlsError, OpenMlsService};
use de_mls::protos::de_mls::messages::v1::{
    AppMessage as AppMessageProto, MemberWelcome, app_message,
};
use de_mls::session::{Conversation, ConversationConfig, ConversationDeps};
use hashgraph_like_consensus::signing::EthereumConsensusSigner;
use openmls::key_packages::KeyPackage;
use openmls::prelude::tls_codec::Serialize as _;
use openmls_traits::signatures::Signer;
use prost::Message;
use shared_traits::{IdentId, IdentIdRef};
use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, instrument, warn};

use crate::inbox_v2::{CIPHER_SUITE, MlsEphemeralPqProvider, MlsIdentityProvider};
use crypto::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};

use crate::IdentityProvider;
use crate::conversation::{ConversationIdRef, ExternalServices, ServiceContext};
use crate::{
    ConvoOutcome, DeliveryService, RegistrationService,
    conversation::{ChatError, Convo, GroupConvo},
};

/// Namespace used for de-mls (GroupV2) keypackages, so they don't collide
/// with the openmls (GroupV1) keypackage registered under the bare account id.
const DEMLS_KEYPACKAGE_NAMESPACE: &str = "demls";

/// Owned, `Clone` identity de-mls's `Sig` can hold. A new type only because the
/// account identity (`S::IP`) is neither owned nor `Clone` here, and
/// `crypto::Identity` implements `IdentityProvider` only under `cfg(test)`.
/// Wrapped in [`MlsIdentityProvider`] to reuse its credential + `Signer`.
#[derive(Clone)]
struct DemlsMember {
    id: IdentId,
    signing: Ed25519SigningKey,
    verifying: Ed25519VerifyingKey,
}

impl DemlsMember {
    fn new(name: impl Into<String>) -> Self {
        let signing = Ed25519SigningKey::generate();
        Self {
            verifying: signing.verifying_key(),
            signing,
            id: IdentId::new(name.into()),
        }
    }
}

impl IdentityProvider for DemlsMember {
    fn id(&self) -> IdentIdRef<'_> {
        &self.id
    }

    fn display_name(&self) -> String {
        self.id.as_str().to_string()
    }

    fn sign(&self, payload: &[u8]) -> Ed25519Signature {
        self.signing.sign(payload)
    }

    fn public_key(&self) -> &Ed25519VerifyingKey {
        &self.verifying
    }
}

/// The de-mls signer: libchat's `MlsIdentityProvider` over a [`DemlsMember`].
/// Already a `Signer` + credential source; we also give it de-mls's `MemberId`
/// so the protocol-side identity bytes match the MLS credential's serialized
/// content (`id().as_str().as_bytes()`).
type DemlsSigner = MlsIdentityProvider<DemlsMember>;

impl MemberId for DemlsSigner {
    fn member_id_bytes(&self) -> &[u8] {
        self.id().as_str().as_bytes()
    }

    fn member_id_display(&self) -> &str {
        self.id().as_str()
    }
}

/// Borrows an existing `IdentityProvider` but reports a namespaced `id()`,
/// so the same identity can register multiple keypackage "flavors"
/// (e.g. openmls vs. de-mls) without colliding in the registry.
struct NamespacedIdentity<'a> {
    inner: &'a dyn IdentityProvider,
    id: IdentId,
}

impl<'a> NamespacedIdentity<'a> {
    fn new(inner: &'a dyn IdentityProvider, namespace: &str) -> Self {
        let id = IdentId::new(Self::prefix(inner.id(), namespace));
        Self { inner, id }
    }

    fn prefix(id: &IdentId, namesapce: &str) -> String {
        format!("{namesapce}|{id}")
    }
}

impl IdentityProvider for NamespacedIdentity<'_> {
    fn id(&self) -> IdentIdRef<'_> {
        &self.id
    }

    fn display_name(&self) -> String {
        self.inner.display_name()
    }

    fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.inner.sign(payload)
    }

    fn public_key(&self) -> &crypto::Ed25519VerifyingKey {
        self.inner.public_key()
    }
}

/// The de-mls MLS service over libchat's PQ provider.
type DemlsMls = OpenMlsService<MlsEphemeralPqProvider>;

/// Reference de-mls plug-in factory over libchat's existing PQ provider. Holds
/// a clone of the signer (to mint key packages) and stashes the provider that
/// minted our key package so the matching `welcome_mls` reuses its private keys
/// — replacing the old key-registry namespacing workaround for private keys.
struct DemlsFactory {
    signer: DemlsSigner,
    pending_provider: RefCell<Option<MlsEphemeralPqProvider>>,
}

impl DemlsFactory {
    fn new(signer: DemlsSigner) -> Self {
        Self {
            signer,
            pending_provider: RefCell::new(None),
        }
    }

    /// Mint a single-use key package into a fresh provider, stashing that
    /// provider so the matching `welcome_mls` can open the welcome with the key
    /// package's private keys.
    fn generate_key_package(&self) -> Result<KeyPackageBytes, ChatError> {
        let provider = MlsEphemeralPqProvider::new().map_err(ChatError::generic)?;
        let bundle = KeyPackage::builder()
            .build(
                CIPHER_SUITE,
                &provider,
                &self.signer,
                self.signer.get_credential(),
            )
            .map_err(ChatError::generic)?;
        let bytes = bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(ChatError::generic)?;
        *self.pending_provider.borrow_mut() = Some(provider);
        Ok(KeyPackageBytes::new(
            bytes,
            self.signer.member_id_bytes().to_vec(),
        ))
    }
}

impl ConversationPluginsFactory for DemlsFactory {
    type Mls = DemlsMls;
    type Scoring = DefaultPeerScoring;
    type StewardList = DefaultStewardList;

    fn create_mls(
        &self,
        conversation_id: String,
        key_package: &[u8],
        signer: &impl Signer,
    ) -> Result<Self::Mls, MlsError> {
        OpenMlsService::new_as_creator(
            conversation_id,
            MlsEphemeralPqProvider::new()?,
            key_package,
            signer,
        )
    }

    fn welcome_mls(&self, welcome_bytes: &[u8]) -> Result<Option<Self::Mls>, MlsError> {
        // Each conversation has its own factory and stash, and welcomes are
        // routed only to the joiner that minted the key package. A missing
        // provider is therefore a logic error here — not a "not for us" case —
        // so surface it instead of silently yielding `None`.
        let provider = self.pending_provider.borrow_mut().take().ok_or_else(|| {
            MlsError::Welcome("no pending key-package provider for this conversation".into())
        })?;
        OpenMlsService::new_from_welcome(welcome_bytes, provider)
    }

    fn make_scoring(&self, config: &ScoringConfig) -> Self::Scoring {
        PeerScoringService::new(
            InMemoryPeerScoreStorage::new(),
            default_score_deltas(),
            config.clone(),
        )
    }

    fn make_steward_list(
        &self,
        conversation_id: &[u8],
        config: StewardListConfig,
    ) -> Self::StewardList {
        DeterministicStewardList::empty(conversation_id.to_vec(), config)
    }
}

struct DemlsSetup {
    signer: DemlsSigner,
    factory: DemlsFactory,
    consensus_storage: <DefaultConsensusPlugin as ConsensusPlugin>::ConsensusStorage,
    consensus_signer: EthereumConsensusSigner,
    app_id: Vec<u8>,            // random bytes; echo-dedup key
    config: ConversationConfig, // the ms-scale test timers, as before
}

impl DemlsSetup {
    fn new(identity_name: String) -> Result<Self, ChatError> {
        let signer = MlsIdentityProvider::new(DemlsMember::new(identity_name));
        let factory = DemlsFactory::new(signer.clone());
        // TODO(config): TEST-ONLY millisecond timers. de-mls deadlines are real
        // wall-clock, so the default 60s timers never fire under fast virtual
        // time. Production needs a real config injected from the caller, not
        // these hardcoded values.
        let config = ConversationConfig {
            commit_inactivity_duration: Duration::from_millis(50),
            freeze_duration: Duration::from_millis(20),
            voting_delay: Duration::from_millis(30),
            election_voting_delay: Duration::from_millis(30),
            consensus_timeout: Duration::from_millis(150),
            proposal_expiration: Duration::from_millis(2000),
            ..ConversationConfig::default()
        };
        Ok(DemlsSetup {
            signer,
            factory,
            consensus_storage: DefaultConsensusPlugin::new_storage(),
            consensus_signer: EthereumConsensusSigner::new(PrivateKeySigner::random()),
            app_id: rand_string(5).as_bytes().to_vec(),
            config,
        })
    }

    /// Call exactly once per Conversation construction.
    fn deps(&self) -> ConversationDeps<'_, DefaultConsensusPlugin, DemlsFactory, DemlsSigner> {
        ConversationDeps {
            plugins: &self.factory,
            consensus: ConsensusServiceFor::<DefaultConsensusPlugin>::new_with_components(
                self.consensus_storage.clone(),
                DefaultConsensusPlugin::new_event_bus(),
                self.consensus_signer.clone(),
                10,
            ),
            signer: self.signer.clone(),
            identity: &self.signer,
            app_id: Arc::from(self.app_id.as_slice()),
            config: self.config.clone(),
            scoring_config: ScoringConfig::default(),
            steward_list_config: StewardListConfig::default(),
        }
    }
}

pub struct GroupV2Convo {
    convo_id: String,
    setup: DemlsSetup,
    conversation: Option<Conversation<DefaultConsensusPlugin, DemlsFactory, DemlsSigner>>,
    /// Member-ids we proposed via add_member. WelcomeReady now fires on
    /// every member; we forward a welcome only to joiners WE invited.
    pending_invites: Vec<Vec<u8>>,
}

impl std::fmt::Debug for GroupV2Convo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupV2Convo")
            .field("convo_id", &self.convo_id)
            .finish_non_exhaustive()
    }
}

fn rand_string(n: usize) -> String {
    let bytes: Vec<u8> = (0..n).map(|_| rand::random::<u8>()).collect();
    hex::encode(bytes)
}

impl GroupV2Convo {
    pub fn new<S: ExternalServices>(
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<Self, ChatError> {
        let setup = DemlsSetup::new(service_ctx.mls_identity.display_name())?;
        let convo_id = rand_string(5);
        let key_package = setup.factory.generate_key_package()?;
        let conversation = Conversation::create(&convo_id, key_package.as_bytes(), setup.deps())?;
        let convo = GroupV2Convo {
            convo_id,
            setup,
            conversation: Some(conversation),
            pending_invites: vec![],
        };

        convo.init(service_ctx)?;

        Ok(convo)
    }

    /// Joiner side: register a fresh key package under the account name,
    /// but do NOT start a conversation. `convo_id` stays empty until
    /// [`Self::accept_welcome`] fills it.
    pub fn new_pending<S: ExternalServices>(
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<Self, ChatError> {
        let name = service_ctx.mls_identity.display_name();
        let setup = DemlsSetup::new(name.clone())?;
        let kp = setup.factory.generate_key_package()?;

        // Namespace the key package so it doesn't collide with the GroupV1
        // key package the registry keys under the bare account id.
        let namespaced =
            NamespacedIdentity::new(&*service_ctx.mls_identity, DEMLS_KEYPACKAGE_NAMESPACE);
        service_ctx
            .registry
            .register(&namespaced, kp.as_bytes().to_vec())
            .map_err(ChatError::generic)?;

        Ok(GroupV2Convo {
            convo_id: String::new(),
            setup,
            conversation: None,
            pending_invites: vec![],
        })
    }

    /// Joiner side: ingest a de-mls welcome handed over the InboxV2 1-1
    /// channel. `from_welcome` attaches MLS and applies the bundled
    /// `ConversationSync` in one call; we then subscribe to the
    /// conversation address and flush the join broadcast.
    #[instrument(name = "groupv2.accept_welcome", skip_all, fields(user_id = %service_ctx.mls_identity.display_name()))]
    pub fn accept_welcome<S: ExternalServices>(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        welcome: &MemberWelcome,
    ) -> Result<(), ChatError> {
        let conv = Conversation::from_welcome(self.setup.deps(), welcome)?
            .ok_or_else(|| ChatError::generic("welcome not addressed to this member"))?;
        self.convo_id = conv.id().to_string();
        self.conversation = Some(conv);
        self.init(service_ctx)?; // subscribe
        self.after_op(service_ctx)?; // flush join broadcast + schedule wakeup
        Ok(())
    }

    fn delivery_address_from_id(convo_id: &str) -> String {
        let hash = Blake2b::<U6>::new()
            .chain_update("delivery_addr|")
            .chain_update(convo_id)
            .finalize();
        hex::encode(hash)
    }

    fn init<S: ExternalServices>(
        &self,
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<(), ChatError> {
        // Configure the delivery service to listen for the required delivery addresses.
        service_ctx
            .ds
            .subscribe(&Self::delivery_address_from_id(&self.convo_id))
            .map_err(ChatError::generic)?;
        Ok(())
    }

    pub fn id(&self) -> ConversationIdRef<'_> {
        &self.convo_id
    }
}

impl<S> Convo<S> for GroupV2Convo
where
    S: ExternalServices,
{
    #[instrument(name = "groupv2.send_content", skip_all, fields(user_id = %service_ctx.mls_identity.display_name(), content))]
    fn send_content(
        &mut self,
        service_ctx: &mut super::ServiceContext<S>,
        content: &[u8],
    ) -> Result<(), ChatError> {
        let conv = self
            .conversation
            .as_mut()
            .ok_or_else(|| ChatError::generic("conversation not found"))?;
        conv.send_message(content.to_vec())?;
        self.after_op(service_ctx)?;
        Ok(())
    }

    #[instrument(name = "groupv2.handle_frame", skip_all, fields(user_id = %service_ctx.mls_identity.display_name()))]
    fn handle_frame(
        &mut self,
        service_ctx: &mut super::ServiceContext<S>,
        encoded_payload: EncryptedPayload,
    ) -> Result<ConvoOutcome, ChatError> {
        let bytes = match encoded_payload.encryption {
            Some(encrypted_payload::Encryption::Plaintext(pt)) => pt.payload,
            _ => {
                return Err(ChatError::generic("Expected plaintext"));
            }
        };
        let frame = GroupV2Frame::decode(bytes.as_ref()).map_err(ChatError::generic)?;
        let inner = match frame.payload {
            Some(GroupV2Payload::DeMlsWrapper(b)) => b.to_vec(),
            _ => return Ok(ConvoOutcome::empty(self.convo_id.clone())),
        };

        let conv = self
            .conversation
            .as_mut()
            .ok_or_else(|| ChatError::generic("no conversation"))?;
        conv.process_inbound(&frame.sender_app_id, &inner)?;
        conv.poll();
        let events = self.after_op(service_ctx)?; // route + publish + re-arm, returns events

        match self.events_to_content(&events) {
            Some(o) => Ok(o),
            None => {
                warn!("returning None as ConvoOutcome");
                Ok(ConvoOutcome::empty(self.convo_id.to_string()))
            }
        }
    }

    #[instrument(name = "groupv2.wakeup", skip_all, fields(user_id = %ctx.mls_identity.display_name()))]
    fn wakeup(&mut self, ctx: &mut ServiceContext<S>) -> Result<(), ChatError> {
        info!(convo = %self.convo_id, "Wakeup");
        let Some(conv) = self.conversation.as_mut() else {
            return Ok(()); // pending joiner: no deadlines exist yet
        };
        let outcome = conv.poll();
        if outcome.leave_requested {
            // Commit ejected us (or join expired). Real handling - drops
            // this convo from its map;
            tracing::warn!(convo = %self.convo_id, "conversation requested teardown");
        }
        self.after_op(ctx)?; // publish what poll produced + re-arm alarm
        Ok(())
    }
}

impl<S> GroupConvo<S> for GroupV2Convo
where
    S: ExternalServices,
{
    fn id(&self) -> ConversationIdRef<'_> {
        &self.convo_id
    }
    #[instrument(name = "groupv2.add_member", skip_all, fields(user_id = %service_ctx.mls_identity.display_name()))]
    fn add_member(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError> {
        // Record who WE invited before touching the conversation: after_op
        // forwards a welcome only to joiners in pending_invites (member-id
        // bytes == account name bytes for LocalDemlsMember).
        let mut kps = Vec::with_capacity(members.len());
        for member in members {
            let device_id = NamespacedIdentity::prefix(member, DEMLS_KEYPACKAGE_NAMESPACE);
            let kp_bytes = service_ctx
                .registry
                .retrieve(&device_id)
                .map_err(ChatError::generic)?
                .ok_or_else(|| ChatError::generic("No key package"))?;
            self.pending_invites
                .push(member.as_str().as_bytes().to_vec());
            kps.push(kp_bytes);
        }

        let conv = self
            .conversation
            .as_mut()
            .ok_or_else(|| ChatError::generic("no conversation"))?;
        for kp_bytes in &kps {
            conv.add_member(kp_bytes)?;
        }
        self.after_op(service_ctx)?;
        Ok(())
    }

    // fn conversation_state(&self) -> Result<ConversationState, ChatError> {
    //     Ok(self
    //         .conversation
    //         .as_ref()
    //         .map(|c| c.state())
    //         .unwrap_or(ConversationState::PendingJoin))
    // }
}

impl GroupV2Convo {
    fn after_op<S: ExternalServices>(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<Vec<ConversationEvent>, ChatError> {
        let Some(conv) = self.conversation.as_ref() else {
            return Ok(Vec::new()); // still pending join — nothing buffered
        };
        // Pull everything first (these are &self, take-all):
        let events = conv.drain_events();
        let outbound = conv.drain_outbound(); // Vec<de_mls::session::Outbound>
        let wakeup = conv.next_wakeup_in();

        // 1. Route welcomes for joiners WE invited (event fires on every member now).
        for evt in &events {
            if let ConversationEvent::WelcomeReady { welcome, .. } = evt {
                for joiner in &welcome.joiner_identities {
                    if let Some(i) = self.pending_invites.iter().position(|p| p == joiner) {
                        self.pending_invites.remove(i);
                        let name = String::from_utf8(joiner.clone()).map_err(ChatError::generic)?;
                        crate::inbox_v2::invite_user_v2(
                            &mut service_ctx.ds,
                            &IdentId::new(name),
                            welcome,
                        )?;
                    }
                }
            }
        }

        // 2. Publish
        for out in outbound {
            let frame = GroupV2Frame {
                payload: Some(GroupV2Payload::DeMlsWrapper(out.payload.into())),
                sender_app_id: out.sender, // was pkt.app_id
            };
            let payload = AddressedEncryptedPayload {
                delivery_address: Self::delivery_address_from_id(&out.conversation_id),
                data: EncryptedPayload {
                    encryption: Some(encrypted_payload::Encryption::Plaintext(Plaintext {
                        payload: frame.encode_to_vec().into(),
                    })),
                },
            };
            service_ctx
                .ds
                .publish(payload.into_envelope(out.conversation_id))
                .map_err(ChatError::generic)?;
        }

        // 3. Re-arm the alarm with the conversation's earliest deadline.
        if let Some(d) = wakeup {
            service_ctx
                .wakeup_service
                .wakeup_in(d, self.convo_id.clone());
        }
        Ok(events)
    }

    fn events_to_content(&self, events: &[ConversationEvent]) -> Option<ConvoOutcome> {
        events.iter().find_map(|evt| match evt {
            ConversationEvent::AppMessage(AppMessageProto {
                payload: Some(app_message::Payload::ConversationMessage(cm)),
            }) => Some(ConvoOutcome {
                convo_id: self.convo_id.clone(),
                content: Some(Content {
                    bytes: cm.message.clone(),
                }),
            }),
            _ => None,
        })
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
