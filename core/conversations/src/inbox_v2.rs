mod identity;
mod mls_provider;

pub use identity::MlsIdentityProvider;
pub(crate) use mls_provider::MlsEphemeralPqProvider;

use chat_proto::logoschat::envelope::EnvelopeV1;
use openmls::prelude::tls_codec::Serialize;
use openmls::prelude::*;
use prost::{Message, Oneof};
use storage::{ConversationKind, ConversationMeta, ConversationStore};

use crate::AddressedEnvelope;
use crate::ChatError;
use crate::DeliveryService;
use crate::RegistrationService;
use crate::conversation::ConversationId;
use crate::conversation::GroupV1Convo;
use crate::outcomes::{ConversationClass, InboxOutcome, NewConversation};
use crate::service_context::{ExternalServices, ServiceContext};
use crate::types::AccountId;
use crate::utils::{blake2b_hex, hash_size};

// Define unique Identifiers derivations used in InboxV2
fn delivery_address_for(account_id: &AccountId) -> String {
    blake2b_hex::<hash_size::AccountId>(&["InboxV2|", "delivery_address|", account_id.as_str()])
}

fn conversation_id_for(account_id: &AccountId) -> String {
    blake2b_hex::<hash_size::ConvoId>(&["InboxV2|", "conversation_id|", account_id.as_str()])
}

/// An Extension trait which extends OpenMlsProvider to add required functionality
/// All MLS based Conversation should use this trait for defining requirements.
pub trait MlsProvider: OpenMlsProvider {
    fn invite_user<DS: DeliveryService>(
        &self,
        ds: &mut DS,
        account_id: &AccountId,
        welcome: &MlsMessageOut,
    ) -> Result<(), ChatError>;
}

/// An PQ focused Conversation initializer.
/// InboxV2 Incorporates an Account based identity system to support PQ based conversation protocols
/// such as MLS.
pub struct InboxV2 {
    // Account_id field is an owned value, so it can be returned via reference.
    account_id: AccountId,
}

impl InboxV2 {
    pub fn new(account_id: AccountId) -> Self {
        Self { account_id }
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Submit MlsKeypackage to registration service
    pub fn register<S: ExternalServices>(
        &self,
        cx: &mut ServiceContext<S>,
    ) -> Result<(), ChatError> {
        let keypackage_bytes = Self::create_keypackage(cx)?.tls_serialize_detached()?;

        // TODO: (P3) Each keypackage can only be used once either enable...
        // "LastResort" package or publish multiple
        cx.registry
            .register(&cx.mls_identity, keypackage_bytes)
            .map_err(ChatError::generic)
    }

    pub fn delivery_address(&self) -> String {
        delivery_address_for(&self.account_id)
    }

    pub fn id(&self) -> String {
        conversation_id_for(&self.account_id)
    }

    pub fn handle_frame<S: ExternalServices>(
        &self,
        payload_bytes: &[u8],
        cx: &mut ServiceContext<S>,
    ) -> Result<InboxOutcome, ChatError> {
        let inbox_frame = InboxV2Frame::decode(payload_bytes)?;

        let Some(payload) = inbox_frame.payload else {
            return Err(ChatError::BadParsing("InboxV2Payload missing"));
        };

        match payload {
            InviteType::GroupV1(group_v1_heavy_invite) => {
                self.handle_heavy_invite(group_v1_heavy_invite, cx)
            }
        }
    }

    fn persist_convo<S: ExternalServices>(
        &self,
        convo: &GroupV1Convo,
        cx: &mut ServiceContext<S>,
    ) -> Result<(), ChatError> {
        // TODO: (P2) Remove remote_convo_id this is an implementation detail specific to PrivateV1
        // TODO: (P3) Implement From<Convo> for ConversationMeta
        let meta = ConversationMeta {
            local_convo_id: convo.id().to_string(),
            remote_convo_id: "0".into(),
            kind: ConversationKind::GroupV1,
        };
        cx.store.save_conversation(&meta)?;
        // TODO: (P1) Persist state
        Ok(())
    }

    fn handle_heavy_invite<S: ExternalServices>(
        &self,
        invite: GroupV1HeavyInvite,
        cx: &mut ServiceContext<S>,
    ) -> Result<InboxOutcome, ChatError> {
        let (msg_in, _rest) = MlsMessageIn::tls_deserialize_bytes(invite.welcome_bytes.as_slice())?;

        let MlsMessageBodyIn::Welcome(welcome) = msg_in.extract() else {
            return Err(ChatError::ProtocolExpectation(
                "something else",
                "Welcome".into(),
            ));
        };

        let convo = GroupV1Convo::new_from_welcome(cx, welcome)?;
        let convo_id: ConversationId = convo.id().to_string();
        self.persist_convo(&convo, cx)?;
        Ok(InboxOutcome {
            new_conversation: NewConversation {
                convo_id,
                class: ConversationClass::Group,
            },
            initial: None,
        })
    }

    fn create_keypackage<S: ExternalServices>(
        cx: &ServiceContext<S>,
    ) -> Result<KeyPackage, ChatError> {
        let capabilities = Capabilities::builder()
            .ciphersuites(vec![
                Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            ])
            .extensions(vec![ExtensionType::ApplicationId])
            .build();
        let a = KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .build(
                Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
                &cx.mls_provider,
                &cx.mls_identity,
                cx.mls_identity.get_credential(),
            )
            .expect("Failed to build KeyPackage");

        Ok(a.key_package().clone())
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct InboxV2Frame {
    #[prost(oneof = "InviteType", tags = "1")]
    pub payload: Option<InviteType>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum InviteType {
    #[prost(message, tag = "1")]
    GroupV1(GroupV1HeavyInvite),
}

#[derive(Clone, PartialEq, Message)]
pub struct GroupV1HeavyInvite {
    #[prost(bytes, tag = "1")]
    pub welcome_bytes: Vec<u8>,
}
