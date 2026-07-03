// This Implementation is a Quick and Dirty Integration of DeMLS into libchat.
// DeMLS and Libchat have different execution models, trait definitions and ownership/lifetimes of objects.
// The easies path is to do a Spike to see what it would take, gather the friction points and then iterate.

use crate::types::AddressedEncryptedPayload;
use crate::{Content, WakeupService};
use alloy::signers::local::PrivateKeySigner;
use blake2::{Blake2b, Digest, digest::consts::U6};
use chat_proto::logoschat::encryption::{EncryptedPayload, Plaintext, encrypted_payload};
use de_mls::protos::de_mls::messages::v1::{
    AppMessage as AppMessageProto, MemberWelcome, app_message,
};
use de_mls::{
    Conversation, ConversationEvent, PeerScoringService, ScoringConfig, default_score_deltas,
    defaults::{DefaultConsensusPlugin, DefaultPeerScoring, InMemoryPeerScoreStorage},
};
use hashgraph_like_consensus::signing::EthereumConsensusSigner;
use openmls::group::MlsGroupCreateConfig;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::{KeyPackageIn, OpenMlsProvider as _, ProtocolVersion};
use prost::Message;
use shared_traits::{IdentId, IdentIdRef};
use std::sync::Arc;
use tracing::{info, instrument, warn};

use crate::IdentityProvider;
use crate::conversation::{ConversationIdRef, ExternalServices, ServiceContext};
use crate::{
    ConvoOutcome, DeliveryService, RegistrationService,
    conversation::{ChatError, Convo, GroupConvo, Identified},
};

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
    conversation: Conversation<DefaultConsensusPlugin, InMemoryPeerScoreStorage>,
    /// Joiners WE invited, as `(member_id, signer_id)`: the de-mls member id
    /// (the joiner's leaf credential content, read from its key package) paired
    /// with the signer id its welcome is delivered to.
    pending_invites: Vec<(Vec<u8>, String)>,
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

fn group_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .build()
}

impl GroupV2Convo {
    pub fn new<S: ExternalServices>(
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<Self, ChatError> {
        let convo_id = rand_string(5);
        let conversation = Conversation::create(
            &convo_id,
            &member_id(service_ctx),
            &service_ctx.mls_provider,
            service_ctx.mls_identity.get_credential(),
            &group_config(),
            &service_ctx.mls_identity,
            &make_consensus(),
            make_scoring(),
            rand_app_id(),
            service_ctx.group_v2_config.clone(),
        )?;
        let convo = GroupV2Convo {
            convo_id,
            conversation,
            pending_invites: vec![],
        };

        convo.init(service_ctx)?;

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
            rand_app_id(),
            service_ctx.group_v2_config.clone(),
        )?
        else {
            return Err(ChatError::generic("welcome not addressed to this member"));
        };

        let mut convo = GroupV2Convo {
            convo_id: conv.id().to_string(),
            conversation: conv,
            pending_invites: vec![],
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

        let outcome = self.conversation.poll(&ctx.mls_provider, &ctx.mls_identity);
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
        // Fetch and validate every key package before proposing any add, so a
        // member with no key package fails the call before it opens proposals
        // for the others. Members are signer ids; the de-mls member id must
        // match the id of the IdentityProvider that generated the key package
        // (its MLS leaf credential content — de-mls matches members by
        // credential), so it is read from the fetched key package rather than
        // assumed equal to the signer id.
        let mut invites = Vec::with_capacity(members.len());
        for member in members {
            let kp_bytes = service_ctx
                .registry
                .retrieve(member.as_str())
                .map_err(ChatError::generic)?
                .ok_or_else(|| ChatError::generic("No key package"))?;
            let key_package_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice())?;
            let keypkg = key_package_in
                .validate(service_ctx.mls_provider.crypto(), ProtocolVersion::Mls10)?;
            let member_id = keypkg
                .leaf_node()
                .credential()
                .serialized_content()
                .to_vec();
            invites.push((member_id, member.to_string(), kp_bytes));
        }

        // Record who WE invited before touching the conversation: after_op
        // forwards a welcome only to joiners in pending_invites. Skip a member
        // de-mls would silently not propose (self, or already in the group) —
        // recording it would strand a pending invite that later matches a
        // re-join and fires a duplicate welcome.
        let mut result = Ok(());
        for (member_id, signer_id, kp_bytes) in invites {
            if member_id == self.conversation.member_id_bytes()
                || self.conversation.members()?.contains(&member_id)
            {
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
                    if let Some(i) = self.pending_invites.iter().position(|(p, _)| p == joiner) {
                        let (_, signer_id) = self.pending_invites.remove(i);
                        crate::inbox_v2::invite_user_v2(
                            &mut service_ctx.ds,
                            &IdentId::new(signer_id),
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
            ConversationEvent::ConversationMessage(AppMessageProto {
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
