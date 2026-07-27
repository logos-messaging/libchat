// This Implementation is a Quick and Dirty Integration of DeMLS into libchat.
// DeMLS and Libchat have different execution models, trait definitions and ownership/lifetimes of objects.
// The easies path is to do a Spike to see what it would take, gather the friction points and then iterate.

use crate::conversation::mls_extensions::{
    ConvoMetaInfo, GROUP_METADATA_EXTENSION_TYPE, capabilities_with_group_metadata,
};
use crate::types::{AddressedEncryptedPayload, ConvoMetadata};
use crate::{Content, WakeupService};
use alloy::signers::local::PrivateKeySigner;
use blake2::{Blake2b, Digest, digest::consts::U6};
use chat_proto::logoschat::encryption::{EncryptedPayload, Plaintext, encrypted_payload};
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
use openmls_traits::crypto::OpenMlsCrypto;
use prost::Message;
use shared_traits::{IdentId, IdentIdRef};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, instrument};

use crate::IdentityProvider;
use crate::conversation::{ConversationIdRef, ExternalServices, ServiceContext};
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
    /// Joiners WE invited, as `(member_id, signer_id)`: the de-mls member id
    /// (the joiner's leaf credential content, read from its key package) paired
    /// with the signer id its welcome is delivered to.
    pending_invites: Vec<(Vec<u8>, String)>,
    /// Liveness anchors: each records when its condition was first seen so we
    /// wait a window before acting. `None` when the condition is inactive. See
    /// [`Self::drive_liveness`].
    commit_anchor: Option<Duration>,
    sync_anchor: Option<Duration>,
    buffered_anchor: Option<Duration>,
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

/// One fetched member: `(de-mls member_id, signer_id, key_package_bytes)`.
type FetchedKeyPackage = (Vec<u8>, String, Vec<u8>);

/// Fetch and dedupe each signer's key package, reading its de-mls member id from
/// the KP leaf credential (de-mls matches by credential, not signer id). Errors
/// if any member has no key package, before any are admitted.
fn fetch_key_packages<S: ExternalServices>(
    service_ctx: &ServiceContext<S>,
    members: &[IdentIdRef],
) -> Result<Vec<FetchedKeyPackage>, ChatError> {
    let mut seen = std::collections::HashSet::new();
    let mut invites = Vec::new();
    for member in members
        .iter()
        .copied()
        .filter(|m| seen.insert(m.as_str().to_string()))
    {
        let kp_bytes = service_ctx
            .registry
            .retrieve(member.as_str())
            .map_err(ChatError::generic)?
            .ok_or_else(|| ChatError::generic("No key package"))?;
        let key_package_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice())?;
        let keypkg =
            key_package_in.validate(service_ctx.mls_provider.crypto(), ProtocolVersion::Mls10)?;
        let member_id = keypkg
            .leaf_node()
            .credential()
            .serialized_content()
            .to_vec();
        invites.push((member_id, member.to_string(), kp_bytes));
    }
    Ok(invites)
}

fn group_config<S: ExternalServices>(
    cx: &mut ServiceContext<S>,
    name: &str,
    desc: &str,
) -> MlsGroupCreateConfig {
    let meta = ConvoMetaInfo::new(name, desc);

    let extensions = Extensions::from_vec(vec![Extension::Unknown(
        GROUP_METADATA_EXTENSION_TYPE,
        UnknownExtension(meta.to_extension_bytes()),
    )])
    .expect("failed to create extensions");

    MlsGroupCreateConfig::builder()
        .ciphersuite(cx.mls_provider.crypto().supported_ciphersuites()[0])
        .capabilities(capabilities_with_group_metadata())
        .use_ratchet_tree_extension(true) // Embed the ratchet tree in the Welcome so joiners can build the group
        .with_group_context_extensions(extensions)
        .build()
}

impl GroupV2Convo {
    pub fn new<S: ExternalServices>(
        service_ctx: &mut ServiceContext<S>,
        name: &str,
        desc: &str,
    ) -> Result<Self, ChatError> {
        let convo_id = rand_string(5);
        let group_config = group_config(service_ctx, name, desc);
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
        )?;
        let convo = GroupV2Convo {
            convo_id,
            conversation,
            pending_invites: vec![],
            commit_anchor: None,
            sync_anchor: None,
            buffered_anchor: None,
        };

        convo.init(service_ctx)?;

        Ok(convo)
    }

    /// Found a group with its initial members admitted in one genesis commit —
    /// one welcome for all, settled and stewarding from epoch 1, no consensus
    /// round (unlike [`Self::new`] + `add_member`). `after_op` routes the genesis
    /// welcome to each founder's InboxV2.
    ///
    /// Assumes `members` is already resolved and deduped, and excludes the
    /// creator. An integrator that can't guarantee that should filter first, the
    /// way `add_member` dedups against live membership.
    pub fn new_with_members<S: ExternalServices>(
        service_ctx: &mut ServiceContext<S>,
        name: &str,
        desc: &str,
        members: &[IdentIdRef],
    ) -> Result<Self, ChatError> {
        let convo_id = rand_string(5);
        let group_config = group_config(service_ctx, name, desc);
        let invites = fetch_key_packages(service_ctx, members)?;
        // `(member_id, key_package_bytes)` slices for the call.
        let founders: Vec<(&[u8], &[u8])> = invites
            .iter()
            .map(|(member_id, _, kp)| (member_id.as_slice(), kp.as_slice()))
            .collect();
        let conversation = Conversation::create_with_members(
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
            &founders,
        )?;
        drop(founders);

        // Route the genesis welcome to each founder's signer id.
        let pending_invites = invites
            .into_iter()
            .map(|(member_id, signer_id, _)| (member_id, signer_id))
            .collect();
        let mut convo = GroupV2Convo {
            convo_id,
            conversation,
            pending_invites,
            commit_anchor: None,
            sync_anchor: None,
            buffered_anchor: None,
        };
        convo.init(service_ctx)?;
        convo.after_op(service_ctx)?;
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
            pending_invites: vec![],
            commit_anchor: None,
            sync_anchor: None,
            buffered_anchor: None,
        };

        convo.init(service_ctx)?; // subscribe
        convo.after_op(service_ctx)?; // flush join broadcast + schedule wakeup

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
    ) -> Result<(), ChatError> {
        self.conversation.send_message(
            &service_ctx.mls_provider,
            &service_ctx.mls_identity,
            content.to_vec(),
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

        self.conversation.process_inbound(
            &service_ctx.mls_provider,
            &service_ctx.mls_identity,
            &frame.sender_app_id,
            &inner,
        )?;
        self.conversation
            .poll(&service_ctx.mls_provider, &service_ctx.mls_identity);
        self.drive_liveness(service_ctx);
        let events = self.after_op(service_ctx)?; // route + publish + re-arm, returns events
        Ok(self.outcome_from_events(&events))
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
        self.drive_liveness(ctx);
        let events = self.after_op(ctx)?; // publish what poll produced + re-arm alarm
        Ok(self.outcome_from_events(&events))
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
        let invites = fetch_key_packages(service_ctx, members)?;

        // pending_invites routes the welcome, so only record a member de-mls
        // will actually add — else a stranded entry fires a spurious welcome
        // later. The roster (members + self, plus adds from this loop) skips the
        // ones de-mls would drop.
        let mut roster: std::collections::HashSet<Vec<u8>> =
            self.conversation.members()?.into_iter().collect();
        roster.insert(self.conversation.member_id_bytes().to_vec());

        let mut result = Ok(());
        for (member_id, signer_id, kp_bytes) in invites {
            if !roster.insert(member_id.clone()) {
                continue;
            }
            self.pending_invites.push((member_id.clone(), signer_id));
            if let Err(e) = self.conversation.add_member(
                &service_ctx.mls_provider,
                &service_ctx.mls_identity,
                &member_id,
                &kp_bytes,
            ) {
                self.pending_invites.pop();
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
        Ok(self
            .pending_invites
            .iter()
            .map(|(member_id, _)| member_id.clone())
            .collect())
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
    /// The window a steward waits before minting its commit candidate: the full
    /// `commit_inactivity`, or the shorter `recovery_commit_window` in a recovery
    /// posture. `drive_liveness` and the `after_op` wakeup fold use the same value
    /// so the scheduled wakeup lands exactly when the window elapses.
    fn commit_delay<S: ExternalServices>(&self, service_ctx: &ServiceContext<S>) -> Duration {
        if self.conversation.in_recovery_posture() {
            service_ctx.demls_liveness.recovery_commit_window
        } else {
            service_ctx.demls_liveness.commit_inactivity
        }
    }

    /// Fire any liveness trigger whose window has elapsed; call once per poll.
    /// Each lever's anchor is armed (and cancelled) by a de-mls event in
    /// [`Self::after_op`], and fired here once its window passes; `after_op`
    /// folds the armed windows into the wakeup so this runs right when one
    /// elapses. libchat times these levers by reacting to de-mls events.
    ///
    /// - **commit** — armed by `CommitWorkReady`, cancelled by `CommitApplied`.
    ///   Every steward mints after `commit_inactivity` (`recovery_commit_window`
    ///   in a recovery posture) and de-mls deterministically selects one, so a
    ///   silent primary is covered by its candidate's absence. A level backstop
    ///   (`pending_commit_work`) also arms it, catching a batch that survived a
    ///   round with no fresh event.
    /// - **sync-resend** — armed by `SyncResendNeeded`, cancelled by
    ///   `ConversationSyncObserved`; a backup covers a silent steward after
    ///   `silent_steward_window`.
    /// - **buffered-propose** — armed by `UpdateRequestReceived` (or the
    ///   `pending_buffered_updates` backstop); a backup covers a silent primary's
    ///   unproposed add/remove after the same window.
    /// - **recovery** — mint each cycle while Layer-3 recovery is open; opening it
    ///   is the `ReelectionExhausted` arm in `after_op`.
    fn drive_liveness<S: ExternalServices>(&mut self, service_ctx: &ServiceContext<S>) {
        let now = service_ctx.demls_clock.now();
        let silent = service_ctx.demls_liveness.silent_steward_window;
        let provider = &service_ctx.mls_provider;
        let signer = &service_ctx.mls_identity;

        // Commit: level backstop for a batch that survived a round (no fresh
        // `CommitWorkReady`), then fire once the window elapses.
        if self.commit_anchor.is_none()
            && self.conversation.is_steward()
            && self.conversation.pending_commit_work().is_some()
        {
            self.commit_anchor = Some(now);
        }
        if let Some(started) = self.commit_anchor
            && now.saturating_sub(started) >= self.commit_delay(service_ctx)
        {
            self.commit_anchor = None;
            if self.conversation.is_steward()
                && let Err(e) = self.conversation.commit_now(provider, signer)
            {
                tracing::warn!(convo = %self.convo_id, error = %e, "commit_now failed");
            }
        }

        // Sync-resend: armed/cancelled by events; fire after the short window.
        if let Some(started) = self.sync_anchor
            && now.saturating_sub(started) >= silent
        {
            self.sync_anchor = None;
            if let Err(e) = self.conversation.share_conversation_sync(provider, signer) {
                tracing::warn!(convo = %self.convo_id, error = %e, "share_conversation_sync failed");
            }
        }

        // Buffered-propose: level backstop (a covering proposal expired → the
        // entry is actionable again with no fresh event), then fire.
        if self.buffered_anchor.is_none() && self.conversation.pending_buffered_updates() > 0 {
            self.buffered_anchor = Some(now);
        }
        if let Some(started) = self.buffered_anchor
            && now.saturating_sub(started) >= silent
        {
            self.buffered_anchor = None;
            if let Err(e) = self.conversation.propose_buffered_updates(provider, signer) {
                tracing::warn!(convo = %self.convo_id, error = %e, "propose_buffered_updates failed");
            }
        }

        // Recovery: mint each cycle while Layer-3 recovery is open.
        if self.conversation.is_in_recovery_mode()
            && let Err(e) = self.conversation.commit_in_recovery(provider, signer)
        {
            tracing::warn!(convo = %self.convo_id, error = %e, "commit_in_recovery failed");
        }
    }

    fn after_op<S: ExternalServices>(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<Vec<ConversationEvent>, ChatError> {
        // Drain events first and react to them before reading outbound/wakeup:
        // request_recovery below emits its own outbound and arms a de-mls
        // deadline, so it must run before we snapshot those.
        let events = self.conversation.drain_events();
        let now = service_ctx.demls_clock.now();

        // 1. React to events: arm/cancel the liveness anchors drive_liveness
        //    fires (see its per-lever contract), route welcomes for joiners WE
        //    invited to their signer id, and open Layer-3 recovery when de-mls's
        //    internal reelection gives up.
        for evt in &events {
            match evt {
                ConversationEvent::WelcomeReady { welcome, .. } => {
                    for joiner in &welcome.joiner_identities {
                        if let Some(i) = self.pending_invites.iter().position(|(p, _)| p == joiner)
                        {
                            let (_, signer_id) = self.pending_invites.remove(i);
                            crate::inbox_v2::invite_user_v2(
                                &mut service_ctx.ds,
                                &IdentId::new(signer_id),
                                welcome,
                            )?;
                        }
                    }
                }
                ConversationEvent::CommitWorkReady { .. } => {
                    // Only a steward commits; a non-steward arming here would just
                    // schedule a wakeup that drive_liveness clears unused. The
                    // level backstop re-arms if this member becomes a steward.
                    if self.conversation.is_steward() {
                        self.commit_anchor.get_or_insert(now);
                    }
                }
                ConversationEvent::CommitApplied(_) => {
                    self.commit_anchor = None;
                }
                ConversationEvent::UpdateRequestReceived { .. } => {
                    self.buffered_anchor.get_or_insert(now);
                }
                ConversationEvent::SyncResendNeeded => {
                    self.sync_anchor.get_or_insert(now);
                }
                ConversationEvent::ConversationSyncObserved => {
                    self.sync_anchor = None;
                }
                ConversationEvent::ReelectionExhausted => {
                    if let Err(e) = self
                        .conversation
                        .request_recovery(&service_ctx.mls_provider, &service_ctx.mls_identity)
                    {
                        tracing::warn!(convo = %self.convo_id, error = %e, "request_recovery failed");
                    }
                }
                _ => {}
            }
        }

        let outbound = self.conversation.drain_outbound(); // Vec<de_mls::session::Outbound>
        let wakeup = self.conversation.next_wakeup_in();

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

        // 3. Re-arm the alarm at the earliest of de-mls's own deadline and our
        //    liveness windows. Each anchor folds in the same delay drive_liveness
        //    used, so the wakeup lands exactly when the window elapses.
        let silent_window = service_ctx.demls_liveness.silent_steward_window;
        let liveness_wakeup = [
            (self.commit_anchor, self.commit_delay(service_ctx)),
            (self.sync_anchor, silent_window),
            (self.buffered_anchor, silent_window),
        ]
        .into_iter()
        .filter_map(|(anchor, delay)| anchor.map(|s| (s + delay).saturating_sub(now)))
        .min();
        let wakeup = match (wakeup, liveness_wakeup) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if let Some(d) = wakeup {
            service_ctx
                .wakeup_service
                .wakeup_in(d, self.convo_id.clone());
        }
        Ok(events)
    }

    fn outcome_from_events(&self, events: &[ConversationEvent]) -> ConvoOutcome {
        let content = events.iter().find_map(|evt| match evt {
            ConversationEvent::ConversationMessage(AppMessageProto {
                payload: Some(app_message::Payload::ConversationMessage(cm)),
            }) => Some(Content {
                bytes: cm.message.clone(),
                encoded_credential: cm.sender.clone(),
            }),
            _ => None,
        });
        let members_changed = events.iter().any(|evt| {
            matches!(
                evt,
                ConversationEvent::CommitApplied(_) | ConversationEvent::WelcomeReady { .. }
            )
        });
        ConvoOutcome {
            convo_id: self.convo_id.clone(),
            content,
            members_changed,
        }
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
