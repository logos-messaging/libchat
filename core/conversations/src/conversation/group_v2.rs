// This Implementation is a Quick and Dirty Integration of DeMLS into libchat.
// DeMLS and Libchat have different execution models, trait definitions and ownership/lifetimes of objects.
// The easies path is to do a Spike to see what it would take, gather the friction points and then iterate.

use crate::types::AddressedEncryptedPayload;
use crate::{Content, WakeupService};
use alloy::signers::local::PrivateKeySigner;
use blake2::{Blake2b, Digest, digest::consts::U6};
use chat_proto::logoschat::encryption::{EncryptedPayload, Plaintext, encrypted_payload};
use de_mls::defaults::{
    DefaultConsensusPlugin, DefaultPeerScoring, DefaultStewardList, InMemoryPeerScoreStorage,
};
use de_mls::protos::de_mls::messages::v1::{
    AppMessage as AppMessageProto, MemberWelcome, app_message,
};
use de_mls::{
    ConsensusPlugin, ConsensusServiceFor, Conversation, ConversationConfig, ConversationEvent,
    DeterministicStewardList, PeerScoringService, ScoringConfig, StewardListConfig,
    default_score_deltas,
};
use hashgraph_like_consensus::signing::EthereumConsensusSigner;
use openmls::key_packages::KeyPackage;
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::{Capabilities, ExtensionType};
use prost::Message;
use shared_traits::{IdentId, IdentIdRef};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, instrument, warn};

use crate::inbox_v2::CIPHER_SUITE;

use crate::IdentityProvider;
use crate::conversation::{ConversationIdRef, ExternalServices, ServiceContext};
use crate::{
    ConvoOutcome, DeliveryService, RegistrationService,
    conversation::{ChatError, Convo, GroupConvo, Identified},
};

/// Namespace used for de-mls (GroupV2) keypackages, so they don't collide
/// with the openmls (GroupV1) keypackage registered under the bare account id.
const DEMLS_KEYPACKAGE_NAMESPACE: &str = "demls";

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

    fn prefix(id: &IdentId, namespace: &str) -> String {
        format!("{namespace}|{id}")
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

/// Local member id bytes — the account identity the protocol matches on,
/// shared with the MLS credential and the consensus member.
fn member_id<S: ExternalServices>(service_ctx: &ServiceContext<S>) -> Vec<u8> {
    service_ctx.mls_identity.id().as_str().as_bytes().to_vec()
}

/// `app_id` for outbound packets / echo-dedup — random per conversation.
fn rand_app_id() -> Arc<[u8]> {
    Arc::from(rand_string(5).as_bytes())
}

/// Peer-scoring plug-in: the library default over in-memory storage.
fn make_scoring() -> DefaultPeerScoring {
    PeerScoringService::new(
        InMemoryPeerScoreStorage::new(),
        default_score_deltas(),
        ScoringConfig::default(),
    )
}

/// Steward-list plug-in: the library default, seedless — the library stamps the
/// conversation-id sort salt when it builds the conversation.
fn make_steward() -> DefaultStewardList {
    DeterministicStewardList::empty(StewardListConfig::default())
}

/// Consensus service: the library default over a fresh in-memory store and a
/// random Ethereum consensus signer.
fn make_consensus() -> ConsensusServiceFor<DefaultConsensusPlugin> {
    ConsensusServiceFor::<DefaultConsensusPlugin>::new_with_components(
        DefaultConsensusPlugin::new_storage(),
        DefaultConsensusPlugin::new_event_bus(),
        EthereumConsensusSigner::new(PrivateKeySigner::random()),
        10,
    )
}

/// TEST-ONLY millisecond timers. de-mls deadlines are real wall-clock, so the
/// default 60s timers never fire under fast virtual time. Production needs a
/// real config injected from the caller, not these hardcoded values.
fn demls_config() -> ConversationConfig {
    ConversationConfig {
        commit_inactivity_duration: Duration::from_millis(50),
        freeze_duration: Duration::from_millis(20),
        voting_delay: Duration::from_millis(30),
        election_voting_delay: Duration::from_millis(30),
        consensus_timeout: Duration::from_millis(150),
        proposal_expiration: Duration::from_millis(2000),
        ..ConversationConfig::default()
    }
}

/// Joiner: mint a single-use key package into the user's shared MLS provider
/// (storing its private keys there so the matching welcome opens), and return
/// the serialized public key package.
fn mint_key_package<S: ExternalServices>(
    service_ctx: &ServiceContext<S>,
) -> Result<Vec<u8>, ChatError> {
    let capabilities = Capabilities::builder()
        .ciphersuites(vec![CIPHER_SUITE])
        .extensions(vec![ExtensionType::ApplicationId])
        .build();
    let bundle = KeyPackage::builder()
        .leaf_node_capabilities(capabilities)
        .build(
            CIPHER_SUITE,
            &service_ctx.mls_provider,
            &service_ctx.mls_identity,
            service_ctx.mls_identity.get_credential(),
        )
        .map_err(ChatError::generic)?;
    bundle
        .key_package()
        .tls_serialize_detached()
        .map_err(ChatError::generic)
}

pub struct GroupV2Convo {
    convo_id: String,
    conversation:
        Option<Conversation<DefaultConsensusPlugin, DefaultPeerScoring, DefaultStewardList>>,
    /// Member-ids we proposed via add_member. We forward a welcome only to joiners WE invited.
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
        let convo_id = rand_string(5);
        let member = member_id(service_ctx);
        let conversation = Conversation::create(
            &convo_id,
            &service_ctx.mls_provider,
            service_ctx.mls_identity.get_credential(),
            CIPHER_SUITE,
            &service_ctx.mls_identity,
            make_scoring(),
            make_steward(),
            make_consensus(),
            rand_app_id(),
            demls_config(),
            &member,
        )?;
        let convo = GroupV2Convo {
            convo_id,
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
        let kp_bytes = mint_key_package(service_ctx)?;

        // Namespace the key package so it doesn't collide with the GroupV1
        // key package the registry keys under the bare account id.
        let namespaced =
            NamespacedIdentity::new(&*service_ctx.mls_identity, DEMLS_KEYPACKAGE_NAMESPACE);
        service_ctx
            .registry
            .register(&namespaced, kp_bytes)
            .map_err(ChatError::generic)?;

        Ok(GroupV2Convo {
            convo_id: String::new(),
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
        let member = member_id(service_ctx);
        let Some(conv) = Conversation::join(
            &service_ctx.mls_provider,
            &welcome.welcome_bytes,
            &welcome.conversation_sync_bytes,
            make_scoring(),
            make_steward(),
            make_consensus(),
            rand_app_id(),
            demls_config(),
            &member,
            &service_ctx.mls_identity,
        )?
        else {
            return Err(ChatError::generic("welcome not addressed to this member"));
        };
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

impl Identified for GroupV2Convo {
    fn id(&self) -> ConversationIdRef<'_> {
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
        conv.send_message(
            &service_ctx.mls_provider,
            content.to_vec(),
            &service_ctx.mls_identity,
        )?;
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
        conv.process_inbound(
            &service_ctx.mls_provider,
            &frame.sender_app_id,
            &inner,
            &service_ctx.mls_identity,
        )?;
        conv.poll(&service_ctx.mls_provider, &service_ctx.mls_identity);
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
        let outcome = conv.poll(&ctx.mls_provider, &ctx.mls_identity);
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
    #[instrument(name = "groupv2.add_member", skip_all, fields(user_id = %service_ctx.mls_identity.display_name()))]
    fn add_member(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError> {
        // Record who WE invited before touching the conversation: after_op
        // forwards a welcome only to joiners in pending_invites (the de-mls
        // member-id is the invitee's id bytes).
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
            conv.add_member(
                &service_ctx.mls_provider,
                kp_bytes,
                &service_ctx.mls_identity,
            )?;
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
                    encoded_credential: cm.sender.clone(),
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
