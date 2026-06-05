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

// Publishing the account → device bundle needs the account key, so these methods
// require the identity to also be an `AccountAuthority`. On testnet that is the
// local `LogosAccount` (account key == device key); an external signer would
// supply its own authority.
impl<IP, DS, CS, RS> InboxV2<IP, DS, RS, CS>
where
    IP: IdentityProvider + AccountAuthority,
    DS: DeliveryService,
    RS: RegistrationService,
    CS: ChatStore,
{
    /// Add this installation's device key to the account's directory bundle.
    ///
    /// Fetches the current (verified) device set, adds this device if absent,
    /// bumps the lamport, re-signs with the account key, and publishes. Safe to
    /// call repeatedly — an unchanged set is simply re-published, which also
    /// refreshes the server's retention clock.
    pub fn publish_device_bundle(&mut self) -> Result<(), ChatError> {
        let authority: &IP = &self.account.borrow();

        let account_id = AccountAuthority::account_id(authority).clone();
        let account_pubkey = authority.account_public_key().clone();
        let device_key = authority.public_key().clone();
        let device_hex = hex::encode(device_key.as_ref());

        // Start from the devices already registered so other installations of
        // this account are preserved across the upsert.
        let existing = self
            .reg_service
            .borrow()
            .fetch(&account_id)
            .map_err(|e| ChatError::Generic(e.to_string()))?;
        let (mut devices, next_lamport) = match existing {
            Some(set) => {
                let mut keys = Vec::with_capacity(set.devices.len() + 1);
                for hex_id in &set.devices {
                    let bytes: [u8; 32] = hex::decode(hex_id)
                        .ok()
                        .and_then(|b| b.try_into().ok())
                        .ok_or_else(|| {
                            ChatError::Generic("directory returned a malformed device id".into())
                        })?;
                    let key = Ed25519VerifyingKey::from_bytes(&bytes).map_err(|_| {
                        ChatError::Generic("directory returned a malformed device key".into())
                    })?;
                    keys.push(key);
                }
                (keys, set.lamport + 1)
            }
            None => (Vec::new(), 0),
        };

        if !devices
            .iter()
            .any(|d| hex::encode(d.as_ref()) == device_hex)
        {
            devices.push(device_key);
        }

        let payload = encode_bundle_payload(&account_pubkey, next_lamport, &devices);
        let signature = AccountAuthority::sign(authority, &payload)
            .map_err(|e| ChatError::Generic(e.to_string()))?;
        let bundle = SignedDeviceBundle {
            account_id,
            payload,
            signature,
        };

        self.reg_service
            .borrow_mut()
            .publish(&bundle)
            .map_err(|e| ChatError::Generic(e.to_string()))
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
