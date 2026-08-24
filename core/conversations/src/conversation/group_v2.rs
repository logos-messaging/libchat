// This Implementation is a Quick and Dirty Integration of DeMLS into libchat.
// DeMLS and Libchat have different execution models, trait definitions and ownership/lifetimes of objects.
// The easies path is to do a Spike to see what it would take, gather the friction points and then iterate.

use crate::conversation::mls_extensions::{
    ConvoMetaInfo, GROUP_METADATA_EXTENSION_TYPE, capabilities_with_group_metadata,
};
use crate::group_v2_status::GroupV2StatusKind;
use crate::types::{AddressedEncryptedPayload, ConvoMetadata};
use crate::{Content, WakeupService};
use alloy::signers::local::PrivateKeySigner;
use blake2::{Blake2b, Digest, digest::consts::U6};
use chat_proto::logoschat::encryption::{EncryptedPayload, Plaintext, encrypted_payload};
use chat_proto::logoschat::reliability::ReliablePayload;
use de_mls::protos::de_mls::messages::v1::{
    AppMessage as AppMessageProto, MemberWelcome, app_message,
};
use de_mls::{
    Conversation, ConversationEvent, MockClock, PeerScoringService, ScoringConfig, WallClock,
    default_score_deltas,
    defaults::{DefaultConsensusPlugin, DefaultPeerScoring, InMemoryPeerScoreStorage},
};
use hashgraph_like_consensus::signing::EthereumConsensusSigner;
use openmls::extensions::{Extension, Extensions, UnknownExtension};
use openmls::group::MlsGroupCreateConfig;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::{KeyPackageIn, OpenMlsProvider as _, ProtocolVersion};
use prost::Message;
use shared_traits::{IdentId, IdentIdRef};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, instrument};

use crate::IdentityProvider;
use crate::conversation::{ConversationIdRef, ExternalServices, MessageId, ServiceContext};
use crate::{
    ConvoOutcome, DeliveryService, RegistrationService,
    conversation::{ChatError, Convo, GroupConvo, Identified},
};

/// The de-mls time source: every conversation deadline (freeze windows,
/// consensus timeouts, auto-votes) and consensus wire timestamp is measured
/// against this clock. Production runs on system time; tests share one
/// `MockClock` with the harness scheduler so virtual time moves the
/// protocol's timers.
#[derive(Debug, Clone, Default)]
pub enum GroupV2Clock {
    #[default]
    System,
    Mock(MockClock),
}

impl WallClock for GroupV2Clock {
    fn now(&self) -> Duration {
        match self {
            GroupV2Clock::System => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default(),
            GroupV2Clock::Mock(clock) => clock.now(),
        }
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
        InMemoryPeerScoreStorage::default(),
        default_score_deltas(),
        ScoringConfig::default(),
    )
}

/// Consensus service: the library default over a fresh in-memory store and a
/// random Ethereum consensus signer.
fn make_consensus() -> DefaultConsensusPlugin {
    DefaultConsensusPlugin::new(EthereumConsensusSigner::new(PrivateKeySigner::random()))
}

pub struct GroupV2Convo {
    convo_id: String,
    conversation: Conversation<DefaultConsensusPlugin, InMemoryPeerScoreStorage, GroupV2Clock>,
    /// Joiners WE invited, keyed by de-mls member id (the joiner's leaf
    /// credential content, read from its key package) → the signer id its
    /// welcome is delivered to.
    pending_invites: HashMap<Vec<u8>, IdentId>,
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

fn group_config(name: &str, desc: &str) -> MlsGroupCreateConfig {
    let meta = ConvoMetaInfo::new(name, desc);

    let extensions = Extensions::from_vec(vec![Extension::Unknown(
        GROUP_METADATA_EXTENSION_TYPE,
        UnknownExtension(meta.to_extension_bytes()),
    )])
    .expect("failed to create extensions");

    MlsGroupCreateConfig::builder()
        .ciphersuite(crate::inbox_v2::CIPHER_SUITE)
        .capabilities(capabilities_with_group_metadata())
        .use_ratchet_tree_extension(true) // Embed the ratchet tree in the Welcome so joiners can build the group
        .with_group_context_extensions(extensions)
        .build()
}

/// A member fetched and ready to admit: the de-mls `member_id` (the KP leaf
/// credential content, which de-mls matches on), the `signer` its welcome
/// routes to, and the `key_package` bytes to commit.
struct FetchedMember {
    member_id: Vec<u8>,
    signer: IdentId,
    key_package: Vec<u8>,
}

/// Fetch and dedupe each signer's key package, reading its de-mls member id from
/// the KP leaf credential (de-mls matches by credential, not signer id). Errors
/// if any member has no key package, before any are admitted.
fn fetch_key_packages<S: ExternalServices>(
    service_ctx: &ServiceContext<S>,
    participants: &[IdentIdRef],
) -> Result<Vec<FetchedMember>, ChatError> {
    let mut seen = HashSet::new();
    participants
        .iter()
        .copied()
        .filter(|m| seen.insert(m.as_str()))
        .map(|member| {
            let key_package = service_ctx
                .registry
                .retrieve(member.as_str())
                .map_err(ChatError::generic)?
                .ok_or_else(|| ChatError::generic("No key package"))?;
            let validated = KeyPackageIn::tls_deserialize(&mut key_package.as_slice())?
                .validate(service_ctx.mls_provider.crypto(), ProtocolVersion::Mls10)?;
            // SECURITY: a validated KeyPackage only proves it is well-formed and
            // self-signed — NOT that it belongs to the signer we asked the registry
            // for. `member_id` below is read from the package's OWN credential and was
            // never checked equal to `member`, so a malicious/compromised registry (or
            // a cache poisoned by an untrusted transport) can return an attacker's
            // package for a victim's id, inserting the attacker's leaf under the
            // victim's identity: confidentiality break + sender-attribution spoof.
            // A signer id is hex(Ed25519 verifying key), so bind the leaf's
            // signature_key (not the spoofable credential bytes) to the requested id.
            let leaf_key = hex::encode(validated.leaf_node().signature_key().as_slice());
            if leaf_key != member.as_str() {
                return Err(ChatError::generic(format!(
                    "key package for {member} is bound to a different signing key ({leaf_key})"
                )));
            }
            let member_id = validated
                .leaf_node()
                .credential()
                .serialized_content()
                .to_vec();
            Ok(FetchedMember {
                member_id,
                signer: member.to_owned(),
                key_package,
            })
        })
        .collect()
}

impl GroupV2Convo {
    pub fn new<S: ExternalServices>(
        service_ctx: &mut ServiceContext<S>,
        name: &str,
        desc: &str,
        participants: &[IdentIdRef],
    ) -> Result<Self, ChatError> {
        let convo_id = rand_string(5);
        let group_config = group_config(name, desc);
        let invites = fetch_key_packages(service_ctx, participants)?;
        let initial_members: Vec<(&[u8], &[u8])> = invites
            .iter()
            .map(|m| (m.member_id.as_slice(), m.key_package.as_slice()))
            .collect();
        let conversation = Conversation::create(
            &convo_id,
            &member_id(service_ctx),
            &service_ctx.mls_provider,
            service_ctx.mls_identity.get_credential(),
            &group_config,
            &service_ctx.mls_identity,
            &make_consensus(),
            make_scoring(),
            service_ctx.demls_clock.clone(),
            rand_app_id(),
            service_ctx.demls_config.clone(),
            &initial_members,
        )?;
        let pending_invites = invites
            .into_iter()
            .map(|m| (m.member_id, m.signer))
            .collect();

        let mut convo = GroupV2Convo {
            convo_id,
            conversation,
            pending_invites,
        };

        convo.init(service_ctx)?;
        convo.after_op(service_ctx)?;
        convo.log_epoch();
        Ok(convo)
    }

    /// Joiner side: ingest a de-mls welcome handed over the InboxV2 1-1
    /// channel. `from_welcome` attaches MLS and applies the bundled
    /// `ConversationSync` in one call; we then subscribe to the
    /// conversation address and flush the join broadcast.
    #[instrument(name = "groupv2.new_from_welcome", skip_all, fields(user_id = %service_ctx.mls_identity.display_name()))]
    pub fn new_from_welcome<S: ExternalServices>(
        service_ctx: &mut ServiceContext<S>,
        welcome: &MemberWelcome,
    ) -> Result<Self, ChatError> {
        let Some(conv) = Conversation::join(
            &member_id(service_ctx),
            &service_ctx.mls_provider,
            &service_ctx.mls_identity,
            &welcome.welcome_bytes,
            &welcome.conversation_sync_bytes,
            &make_consensus(),
            make_scoring(),
            service_ctx.demls_clock.clone(),
            rand_app_id(),
            service_ctx.demls_config.clone(),
        )?
        else {
            return Err(ChatError::generic("welcome not addressed to this member"));
        };

        let mut convo = GroupV2Convo {
            convo_id: conv.id().to_string(),
            conversation: conv,
            pending_invites: HashMap::new(),
        };

        convo.init(service_ctx)?; // subscribe
        convo.after_op(service_ctx)?; // flush join broadcast + schedule wakeup
        convo.log_epoch();

        Ok(convo)
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
    ) -> Result<MessageId, ChatError> {
        let reliable = service_ctx.causal.on_send(
            &self.convo_id,
            service_ctx.mls_identity.id().as_str(),
            content,
        );

        self.conversation.send_message(
            &service_ctx.mls_provider,
            &service_ctx.mls_identity,
            reliable.encode_to_vec(),
        )?;
        self.after_op(service_ctx)?;
        Ok(reliable.message_id)
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

        self.conversation.process_inbound(
            &service_ctx.mls_provider,
            &service_ctx.mls_identity,
            &frame.sender_app_id,
            &inner,
        )?;
        self.conversation
            .poll(&service_ctx.mls_provider, &service_ctx.mls_identity);
        let events = self.after_op(service_ctx)?; // route + publish + re-arm, returns events
        self.outcome_from_events(service_ctx, &events)
    }

    #[instrument(name = "groupv2.wakeup", skip_all, fields(user_id = %ctx.mls_identity.display_name()))]
    fn wakeup(&mut self, ctx: &mut ServiceContext<S>) -> Result<ConvoOutcome, ChatError> {
        info!(convo = %self.convo_id, "Wakeup");

        let poll_outcome = self.conversation.poll(&ctx.mls_provider, &ctx.mls_identity);
        if poll_outcome.leave_requested {
            // Commit ejected us (or join expired). Real handling - drops
            // this convo from its map;
            tracing::warn!(convo = %self.convo_id, "conversation requested teardown");
        }
        let events = self.after_op(ctx)?; // publish what poll produced + re-arm alarm
        self.outcome_from_events(ctx, &events)
    }

    fn members(&self) -> Result<Vec<Vec<u8>>, ChatError> {
        // Guarantee the local member is listed so callers see the full roster.
        let mut members = self.conversation.members()?;
        let self_id = self.conversation.member_id_bytes().to_vec();
        if !members.contains(&self_id) {
            members.push(self_id);
        }
        Ok(members)
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
        // Fetch every signer's key package + de-mls member id up front (deduped),
        // failing before any proposal opens if one has no key package.
        let members_to_add = fetch_key_packages(service_ctx, members)?;
        let existing: HashSet<Vec<u8>> = self.conversation.members()?.into_iter().collect();

        let mut result = Ok(());
        for FetchedMember {
            member_id,
            signer,
            key_package,
        } in members_to_add
        {
            if existing.contains(&member_id) {
                continue;
            }
            self.pending_invites.insert(member_id.clone(), signer);
            if let Err(e) = self.conversation.add_member(
                &service_ctx.mls_provider,
                &service_ctx.mls_identity,
                &member_id,
                &key_package,
            ) {
                self.pending_invites.remove(&member_id);
                result = Err(e.into());
                break;
            }
        }
        // Flush even on a mid-loop failure: proposals already opened must be
        // published and the wakeup re-armed, or they sit dormant until an
        // unrelated frame drives the conversation.
        let flushed = self.after_op(service_ctx).map(drop);
        result.and(flushed)
    }

    fn pending_members(&self) -> Result<Vec<Vec<u8>>, ChatError> {
        Ok(self.pending_invites.keys().cloned().collect())
    }

    fn metadata(&self) -> Option<ConvoMetadata> {
        let res = self.conversation.extensions().iter().find_map(|ext| {
            if let Extension::Unknown(ext_type, UnknownExtension(bytes)) = ext
                && *ext_type == GROUP_METADATA_EXTENSION_TYPE
            {
                return ConvoMetaInfo::from_extension_bytes(bytes).ok();
            };
            None
        });

        res.map(Into::into)
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
        // Pull everything first (these are &self, take-all):
        let events = self.conversation.drain_events();
        let outbound = self.conversation.drain_outbound(); // Vec<de_mls::session::Outbound>
        let wakeup = self.conversation.next_wakeup_in();

        // 1. Route welcomes for joiners WE invited (event fires on every member
        //    now). The welcome travels to the joiner's signer id (where its
        //    InboxV2 listens), not its de-mls member id.
        for evt in &events {
            if let ConversationEvent::WelcomeReady { welcome, .. } = evt {
                for joiner in &welcome.joiner_identities {
                    if let Some(signer_id) = self.pending_invites.remove(joiner) {
                        crate::inbox_v2::invite_user_v2(&mut service_ctx.ds, &signer_id, welcome)?;
                    }
                }
            }
        }

        // 2. Record what the conversation said about running itself, so a
        //    client can surface a commit round that is missing candidates or a
        //    step that did not go through.
        for evt in &events {
            let kind = match evt {
                ConversationEvent::PhaseChange(state) => GroupV2StatusKind::Phase(*state),
                ConversationEvent::CommitRoundProgress { received, expected } => {
                    GroupV2StatusKind::CommitRound {
                        received: *received,
                        expected: *expected,
                    }
                }
                ConversationEvent::Error { operation, message } => GroupV2StatusKind::Failed {
                    operation: operation.clone(),
                    message: message.clone(),
                },
                _ => continue,
            };
            service_ctx.group_v2_status.record(&self.convo_id, kind);
        }
        if events
            .iter()
            .any(|evt| matches!(evt, ConversationEvent::CommitApplied(_)))
        {
            self.log_epoch();
        }

        // 3. Publish
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

        // 4. Re-arm the alarm with the conversation's earliest deadline.
        if let Some(d) = wakeup {
            service_ctx
                .wakeup_service
                .wakeup_in(d, self.convo_id.clone());
        }
        Ok(events)
    }

    /// Names this member's view of the group's state. Two members at the same
    /// epoch holding different authenticators have forked; a member at a lower
    /// epoch has only fallen behind. The pair carries that meaning only
    /// compared across members, never on one alone.
    fn log_epoch(&self) {
        let epoch = match self.conversation.epoch_and_retry() {
            Ok((epoch, _)) => epoch,
            Err(e) => {
                tracing::warn!(convo = %self.convo_id, error = %e, "epoch unavailable");
                return;
            }
        };
        info!(
            convo = %self.convo_id,
            epoch,
            authenticator = %hex::encode(self.conversation.epoch_authenticator()),
            "epoch reached"
        );
    }

    /// Turn drained de-mls events into a [`ConvoOutcome`], unwrapping the
    /// message from its causal-history envelope.
    ///
    /// An outcome holds one message and de-mls emits at most one per frame, so
    /// the first wins. A second would be dropped without being recorded as
    /// seen, leaving a later reference to report it missing.
    fn outcome_from_events<S: ExternalServices>(
        &self,
        service_ctx: &ServiceContext<S>,
        events: &[ConversationEvent],
    ) -> Result<ConvoOutcome, ChatError> {
        let content = events
            .iter()
            .find_map(|evt| match evt {
                ConversationEvent::ConversationMessage(AppMessageProto {
                    payload: Some(app_message::Payload::ConversationMessage(cm)),
                }) => Some(cm),
                _ => None,
            })
            .map(|cm| -> Result<Content, ChatError> {
                let reliable =
                    ReliablePayload::decode(cm.message.as_slice()).map_err(ChatError::generic)?;
                service_ctx.causal.on_receive(&self.convo_id, &reliable);
                Ok(Content {
                    bytes: reliable.content.to_vec(),
                    encoded_credential: cm.sender.clone(),
                })
            })
            .transpose()?;

        let members_changed = events.iter().any(|evt| {
            matches!(
                evt,
                ConversationEvent::CommitApplied(_) | ConversationEvent::WelcomeReady { .. }
            )
        });
        Ok(ConvoOutcome {
            convo_id: self.convo_id.clone(),
            content,
            members_changed,
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
