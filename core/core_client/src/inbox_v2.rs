use std::cell::RefCell;
use std::ops::Deref;
use std::rc::Rc;

use chat_proto::logoschat::envelope::EnvelopeV1;
use de_mls::protos::de_mls::messages::v1::MemberWelcome;
use openmls::prelude::tls_codec::Serialize;
use openmls::prelude::*;
use openmls_libcrux_crypto::CryptoProvider as LibcruxCryptoProvider;
use openmls_memory_storage::MemoryStorage;
use openmls_traits::signatures::Signer;
use openmls_traits::signatures::SignerError;
use prost::{Message, Oneof};
use storage::ChatStore;
use storage::ConversationMeta;
use tracing::info;
use tracing::instrument;

use crate::AccountId;
use crate::AddressedEnvelope;
use crate::ChatError;
use crate::DeliveryService;
use crate::IdentityProvider;
use crate::RegistrationService;
use crate::conversation::BaseConvo;
use crate::conversation::BaseGroupConvo;
use crate::conversation::ExternalServices;
use crate::conversation::GroupV2Convo;
use crate::conversation::ServiceContext;
use crate::conversation::{GroupV1Convo, Id};
use crate::utils::{blake2b_hex, hash_size};

// Define unique Identifiers derivations used in InboxV2
fn delivery_address_for(account_id: &AccountId) -> String {
    blake2b_hex::<hash_size::AccountId>(&["InboxV2|", "delivery_address|", account_id.as_str()])
}

fn conversation_id_for(account_id: &AccountId) -> String {
    blake2b_hex::<hash_size::ConvoId>(&["InboxV2|", "conversation_id|", account_id.as_str()])
}

#[derive(Debug)]
pub struct MlsIdentityProvider<T: IdentityProvider>(pub T);

impl<T: IdentityProvider> MlsIdentityProvider<T> {
    pub fn get_credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.0.friendly_name().into()).into(),
            signature_key: self.0.public_key().as_ref().into(),
        }
    }
}

impl<T: IdentityProvider> Deref for MlsIdentityProvider<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: IdentityProvider> IdentityProvider for MlsIdentityProvider<T> {
    fn account_id(&self) -> &AccountId {
        self.0.account_id()
    }

    fn friendly_name(&self) -> String {
        self.0.friendly_name()
    }

    fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.0.sign(payload)
    }

    fn public_key(&self) -> &crypto::Ed25519VerifyingKey {
        self.0.public_key()
    }
}

impl<T: IdentityProvider> Signer for MlsIdentityProvider<T> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.0.sign(payload).as_ref().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
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

/// Deliver a de-mls welcome to `account_id` over its InboxV2 1-1 channel.
/// Function mirroring the GroupV1 `invite_user` path, but carrying a de-mls `MemberWelcome`.
pub fn invite_user_v2<DS: DeliveryService>(
    ds: &mut DS,
    account_id: &AccountId,
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

/// This is a PQ based provider that uses in memory storage.
pub struct MlsEphemeralPqProvider {
    crypto: LibcruxCryptoProvider,
    storage: MemoryStorage,
}

impl MlsEphemeralPqProvider {
    pub fn new() -> Result<Self, CryptoError> {
        let crypto = LibcruxCryptoProvider::new()?;
        let storage = MemoryStorage::default();

        Ok(Self { crypto, storage })
    }
}

impl MlsProvider for MlsEphemeralPqProvider {
    fn invite_user<DS: DeliveryService>(
        &self,
        ds: &mut DS,
        account_id: &AccountId,
        welcome: &MlsMessageOut,
    ) -> Result<(), ChatError> {
        let invite = GroupV1HeavyInvite {
            welcome_bytes: welcome.to_bytes().map_err(ChatError::generic)?,
        };

        let frame = InboxV2Frame {
            payload: Some(InviteType::GroupV1(invite)),
        };

        let envelope = EnvelopeV1 {
            conversation_hint: conversation_id_for(account_id),
            salt: 0,
            payload: frame.encode_to_vec().into(),
        };

        let outbound_msg = AddressedEnvelope {
            delivery_address: delivery_address_for(account_id),
            data: envelope.encode_to_vec(),
        };

        ds.publish(outbound_msg).map_err(ChatError::generic)?;
        Ok(())
    }
}

impl OpenMlsProvider for MlsEphemeralPqProvider {
    type CryptoProvider = LibcruxCryptoProvider;
    type RandProvider = LibcruxCryptoProvider;
    type StorageProvider = openmls_memory_storage::MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

/// An PQ focused Conversation initializer.
/// InboxV2 Incorporates an Account based identity system to support PQ based conversation protocols
/// such as MLS.
pub struct InboxV2<CS> {
    account_id: AccountId,
    _store: Rc<RefCell<CS>>,
    mls_provider: Rc<RefCell<MlsEphemeralPqProvider>>,
    pending_demls: RefCell<Option<GroupV2Convo>>,
}

impl<CS: ChatStore> InboxV2<CS> {
    pub fn new<S: ExternalServices>(
        service_ctx: &mut ServiceContext<S>,
        _store: Rc<RefCell<CS>>,
    ) -> Self {
        // Avoid referencing a temporary value by caching it.
        let account_id = service_ctx.identity_provider.account_id().clone();
        let provider = MlsEphemeralPqProvider::new().unwrap();
        Self {
            account_id,
            _store,
            mls_provider: Rc::new(RefCell::new(provider)),
            pending_demls: RefCell::new(None),
        }
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn delivery_address(&self) -> String {
        delivery_address_for(&self.account_id)
    }

    pub fn id(&self) -> String {
        conversation_id_for(&self.account_id)
    }

    /// Submit MlsKeypackage to registration service
    pub fn register<S: ExternalServices>(
        &self,
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<(), ChatError> {
        let mls_ident = MlsIdentityProvider(&service_ctx.identity_provider);
        let keypackage_bytes = self
            .create_keypackage(&mls_ident)?
            .tls_serialize_detached()?;

        // TODO: (P3) Each keypackage can only be used once either enable...
        // "LastResort" package or publish multiple
        service_ctx
            .rs
            .register(
                &service_ctx.identity_provider.friendly_name(),
                keypackage_bytes,
            )
            .map_err(ChatError::generic)?;

        // de-mls (GroupV2) joiner: build a conversation-less User and register
        // its de-mls key package under the same account name. This shadows the
        // OpenMLS key package above in the registry; GroupV2 is the path the
        // de-mls integration exercises.
        *self.pending_demls.borrow_mut() = Some(GroupV2Convo::new_pending(service_ctx)?);

        Ok(())
    }

    #[allow(unused)]
    pub fn create_group_v1<S: ExternalServices>(
        &self,
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<GroupV1Convo<MlsEphemeralPqProvider>, ChatError> {
        let mls_ident = MlsIdentityProvider(&service_ctx.identity_provider);
        GroupV1Convo::new(mls_ident, self.mls_provider.clone())
    }

    pub fn create_group_v2<S: ExternalServices>(
        &self,
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<GroupV2Convo, ChatError> {
        GroupV2Convo::new(service_ctx)
    }

    fn create_keypackage<IP: IdentityProvider>(
        &self,
        signer: &MlsIdentityProvider<IP>,
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
                &*self.mls_provider.borrow(),
                signer,
                signer.get_credential(),
            )
            .expect("Failed to build KeyPackage");

        Ok(a.key_package().clone())
    }
}

impl<CS: ChatStore> InboxV2<CS> {
    #[instrument(name = "inboxv2.handle_frame", skip_all, fields(user_id = %service_ctx.identity_provider.friendly_name()))]
    pub fn handle_frame<S: ExternalServices>(
        &self,
        service_ctx: &mut ServiceContext<S>,
        payload_bytes: &[u8],
    ) -> Result<Option<Box<dyn BaseGroupConvo<S>>>, ChatError> {
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

    fn handle_heavy_invite<S: ExternalServices>(
        &self,
        service_ctx: &mut ServiceContext<S>,
        invite: GroupV1HeavyInvite,
    ) -> Result<GroupV1Convo<MlsEphemeralPqProvider>, ChatError> {
        let (msg_in, _rest) = MlsMessageIn::tls_deserialize_bytes(invite.welcome_bytes.as_slice())?;

        let MlsMessageBodyIn::Welcome(welcome) = msg_in.extract() else {
            return Err(ChatError::Generic("Expected Welcome".into()));
        };

        let convo = GroupV1Convo::new_from_welcome(self.mls_provider.clone(), welcome)?;
        convo.init(service_ctx)?;
        self.persist_convo(convo.id())?;
        Ok(convo)
    }

    fn persist_convo(&self, local_convo_id: &str) -> Result<(), ChatError> {
        let meta = ConversationMeta {
            local_convo_id: local_convo_id.to_string(),
            remote_convo_id: "0".into(),
            kind: storage::ConversationKind::GroupV1,
        };
        self._store
            .borrow_mut()
            .save_conversation(&meta)
            .map_err(ChatError::generic)
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
