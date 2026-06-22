mod identity;
mod mls_provider;

use chat_proto::logoschat::envelope::EnvelopeV1;
use crypto::Ed25519VerifyingKey;
use de_mls::protos::de_mls::messages::v1::MemberWelcome;
use openmls::prelude::tls_codec::Serialize;
use openmls::prelude::*;
use prost::{Message, Oneof};
use std::cell::RefCell;
use storage::{ConversationKind, ConversationMeta, ConversationStore};
use tracing::info;
use tracing::instrument;

pub use identity::MlsIdentityProvider;
pub(crate) use mls_provider::MlsEphemeralPqProvider;

use crate::ChatError;
use crate::DeliveryService;
use crate::RegistrationService;
use crate::conversation::GroupConvo;
use crate::conversation::GroupV1Convo;
use crate::conversation::GroupV2Convo;
use crate::conversation::Identified as _;
use crate::service_context::{ExternalServices, ServiceContext};
use crate::utils::{blake2b_hex, hash_size};
use crate::{
    AccountAuthority, AccountDirectory, AddressedEnvelope, SignedDeviceBundle,
    encode_bundle_payload,
};
use crate::{IdentId, IdentIdRef, IdentityProvider};

// Downgraded from MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 until demls accepts an external provider
pub(crate) const CIPHER_SUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

// Define unique Identifiers derivations used in InboxV2
fn delivery_address_for(ident_id: IdentIdRef) -> String {
    blake2b_hex::<hash_size::DeliveryAddr>(&["InboxV2|", "delivery_address|", ident_id.as_str()])
}

fn conversation_id_for(ident_id: IdentIdRef) -> String {
    blake2b_hex::<hash_size::ConvoId>(&["InboxV2|", "conversation_id|", ident_id.as_str()])
}

/// An Extension trait which extends OpenMlsProvider to add required functionality
/// All MLS based Conversation should use this trait for defining requirements.
pub trait MlsProvider: OpenMlsProvider {
    fn invite_user<DS: DeliveryService>(
        &self,
        ds: &mut DS,
        ident_id: IdentIdRef,
        welcome: &MlsMessageOut,
    ) -> Result<(), ChatError>;
}

/// Deliver a de-mls welcome to `account_id` over its InboxV2 1-1 channel.
/// Function mirroring the GroupV1 `invite_user` path, but carrying a de-mls `MemberWelcome`.
pub fn invite_user_v2<DS: DeliveryService>(
    ds: &mut DS,
    account_id: IdentIdRef,
    welcome: &MemberWelcome,
) -> Result<(), ChatError> {
    let frame = InboxV2Frame {
        payload: Some(InviteType::GroupV2(welcome.encode_to_vec())),
    };
    let envelope = EnvelopeV1 {
        conversation_hint: conversation_id_for(account_id),
        salt: 0,
        payload: frame.encode_to_vec().into(),
    };
    ds.publish(AddressedEnvelope {
        delivery_address: delivery_address_for(account_id),
        data: envelope.encode_to_vec(),
    })
    .map_err(ChatError::generic)
}

/// An PQ focused Conversation initializer.
/// InboxV2 Incorporates an Account based identity system to support PQ based conversation protocols
/// such as MLS.
pub struct InboxV2 {
    // Account_id field is an owned value, so it can be returned via reference.
    ident_id: IdentId,
    pending_demls: RefCell<Option<GroupV2Convo>>,
}

impl InboxV2 {
    pub fn new(ident_id: IdentId) -> Self {
        Self {
            ident_id,
            pending_demls: RefCell::new(None),
        }
    }

    pub fn ident_id(&self) -> IdentIdRef<'_> {
        &self.ident_id
    }

    /// Submit MlsKeypackage to registration service
    pub fn register<S: ExternalServices>(
        &mut self,
        cx: &mut ServiceContext<S>,
    ) -> Result<(), ChatError> {
        let keypackage_bytes = Self::create_keypackage(cx)?.tls_serialize_detached()?;

        // TODO: (P3) Each keypackage can only be used once either enable...
        // "LastResort" package or publish multiple
        cx.registry
            .register(&cx.mls_identity, keypackage_bytes)
            .map_err(ChatError::generic)?;

        // de-mls (GroupV2) joiner: build a conversation-less User and register
        // its de-mls key package under the same account name. This shadows the
        // OpenMLS key package above in the registry; GroupV2 is the path the
        // de-mls integration exercises.
        *self.pending_demls.borrow_mut() = Some(GroupV2Convo::new_pending(cx)?);

        Ok(())
    }

    pub fn delivery_address(&self) -> String {
        delivery_address_for(&self.ident_id)
    }

    pub fn id(&self) -> String {
        conversation_id_for(&self.ident_id)
    }

    #[instrument(name = "inboxV2.handle_frame", skip_all, fields(user_id = %service_ctx.mls_identity.display_name()))]
    pub fn handle_frame<S: ExternalServices>(
        &self,
        service_ctx: &mut ServiceContext<S>,
        payload_bytes: &[u8],
    ) -> Result<Option<Box<dyn GroupConvo<S>>>, ChatError> {
        // On a broadcast transport the inbox address also receives traffic
        // that isn't an invite (or that prost decodes into an empty frame).
        // Treat anything we can't interpret as "not for us" and skip it,
        // rather than failing the whole poll cycle.
        let Ok(inbox_frame) = InboxV2Frame::decode(payload_bytes) else {
            return Ok(None);
        };
        let Some(payload) = inbox_frame.payload else {
            return Ok(None);
        };

        match payload {
            InviteType::GroupV1(inv) => {
                Ok(Some(Box::new(self.handle_heavy_invite(service_ctx, inv)?)))
            }
            InviteType::GroupV2(welcome_bytes) => {
                info!("Process WelcomeMessage");
                let mut convo = self
                    .pending_demls
                    .borrow_mut()
                    .take()
                    .ok_or_else(|| ChatError::generic("no pending de-mls convo"))?;
                let mw =
                    MemberWelcome::decode(welcome_bytes.as_slice()).map_err(ChatError::generic)?;
                convo.accept_welcome(service_ctx, &mw)?;
                Ok(Some(Box::new(convo)))
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
        cx: &mut ServiceContext<S>,
        invite: GroupV1HeavyInvite,
    ) -> Result<GroupV1Convo, ChatError> {
        let (msg_in, _rest) = MlsMessageIn::tls_deserialize_bytes(invite.welcome_bytes.as_slice())?;

        let MlsMessageBodyIn::Welcome(welcome) = msg_in.extract() else {
            return Err(ChatError::ProtocolExpectation(
                "something else",
                "Welcome".into(),
            ));
        };

        let convo = GroupV1Convo::new_from_welcome(cx, welcome)?;
        self.persist_convo(&convo, cx)?;

        Ok(convo)
    }

    fn create_keypackage<S: ExternalServices>(
        cx: &ServiceContext<S>,
    ) -> Result<KeyPackage, ChatError> {
        let capabilities = Capabilities::builder()
            .ciphersuites(vec![CIPHER_SUITE])
            .extensions(vec![ExtensionType::ApplicationId])
            .build();
        let a = KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .build(
                CIPHER_SUITE,
                &cx.mls_provider,
                &cx.mls_identity,
                cx.mls_identity.get_credential(),
            )
            .expect("Failed to build KeyPackage");

        Ok(a.key_package().clone())
    }
}

// Publishing the account → device bundle needs the account key, so this method
// is available only when the registry also implements `AccountDirectory`. The
// signing authority is the `LogosAccount` wrapped by `mls_identity`; on testnet
// that is a local key (account key == device key), while an external signer
// would supply its own authority.
impl InboxV2 {
    /// Add this installation's device key to the account's directory bundle.
    ///
    /// Fetches the current (verified) device set, adds this device if absent,
    /// bumps the lamport, re-signs with the account key, and publishes. Safe to
    /// call repeatedly — an unchanged set is simply re-published, which also
    /// refreshes the server's retention clock.
    pub fn publish_device_bundle<S: ExternalServices>(
        &self,
        cx: &mut ServiceContext<S>,
    ) -> Result<(), ChatError> {
        // On testnet `mls_identity` doubles as the `AccountAuthority` — the
        // account key is the installation's own key.
        let authority = &cx.mls_identity;

        let account_pub = AccountAuthority::account_pub(authority).clone();
        let device_key = cx.mls_identity.public_key().clone();
        let device_hex = hex::encode(device_key.as_ref());

        // Start from the devices already registered so other installations of
        // this account are preserved across the upsert.
        let existing = cx
            .registry
            .fetch(&account_pub)
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

        let payload = encode_bundle_payload(next_lamport, &devices);
        let signature = AccountAuthority::sign(authority, &payload)
            .map_err(|e| ChatError::Generic(e.to_string()))?;
        let bundle = SignedDeviceBundle {
            account_pub,
            payload,
            signature,
        };

        cx.registry
            .publish(&bundle)
            .map_err(|e| ChatError::Generic(e.to_string()))
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct InboxV2Frame {
    #[prost(oneof = "InviteType", tags = "1, 2")]
    pub payload: Option<InviteType>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum InviteType {
    #[prost(message, tag = "1")]
    GroupV1(GroupV1HeavyInvite),
    #[prost(bytes, tag = "2")]
    GroupV2(Vec<u8>),
}

#[derive(Clone, PartialEq, Message)]
pub struct GroupV1HeavyInvite {
    #[prost(bytes, tag = "1")]
    pub welcome_bytes: Vec<u8>,
}
