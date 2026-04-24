use std::cell::{Ref, RefCell};
use std::rc::Rc;

use chat_proto::logoschat::envelope::EnvelopeV1;
use crypto::Ed25519SigningKey;
use crypto::Ed25519VerifyingKey;
use openmls::prelude::tls_codec::Serialize;
use openmls::prelude::*;
use openmls_libcrux_crypto::Provider as LibcruxProvider;
use openmls_traits::signatures::Signer;
use prost::{Message, Oneof};
use std::sync::atomic::{AtomicUsize, Ordering};
use storage::ChatStore;
use storage::ConversationMeta;

use crate::AddressedEnvelope;
use crate::ChatError;
use crate::DeliveryService;
use crate::RegistrationService;
use crate::conversation::GroupConvo;
use crate::conversation::group_v1::{MlsCtx, MlsInitializer};
use crate::conversation::{GroupV1Convo, IdentityProvider};
use crate::ctx::ClientCtx;
use crate::utils::{blake2b_hex, hash_size};

static ACCOUNT_COUNTER: AtomicUsize = AtomicUsize::new(0);
const ACCOUNT_NAMES: &[&str] = &["Saro", "Raya", "Pax"];
#[derive(Clone)]
pub struct LogosAccount {
    id: String,
    signing_key: Ed25519SigningKey,
    // x25519_key: crypto::PrivateKey,
}

impl LogosAccount {
    pub fn new() -> Self {
        let idx = ACCOUNT_COUNTER.fetch_add(1, Ordering::Relaxed);

        let id = if idx < ACCOUNT_NAMES.len() {
            ACCOUNT_NAMES[idx % ACCOUNT_NAMES.len()].to_string()
        } else {
            use rand_core::{OsRng, RngCore};
            const CHARSET: &[u8] =
                b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            let i: String = (0..8)
                .map(|_| {
                    let idx = (OsRng.next_u32() as usize) % CHARSET.len();
                    CHARSET[idx] as char
                })
                .collect();
            i
        };
        Self {
            id,
            signing_key: Ed25519SigningKey::generate(),
            // x25519_key: crypto::PrivateKey::random(),
        }
    }
}

impl Signer for LogosAccount {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, openmls_traits::signatures::SignerError> {
        Ok(self.signing_key.sign(payload).as_ref().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

impl IdentityProvider for LogosAccount {
    fn friendly_name(&self) -> String {
        self.id.clone()
    }

    fn public_key(&self) -> Ed25519VerifyingKey {
        self.signing_key.verifying_key()
    }
}

#[derive(Clone)]
pub struct MlsContext<Init: MlsInitializer> {
    pub ident_provider: LogosAccount,
    pub initializer: Init,
    provider: Rc<RefCell<LibcruxProvider>>,
}

impl<Init: MlsInitializer + Clone> MlsCtx for MlsContext<Init> {
    type IDENT = LogosAccount;
    type INIT = Init;

    fn ident(&self) -> &LogosAccount {
        &self.ident_provider
    }

    fn provider(&self) -> Ref<'_, LibcruxProvider> {
        self.provider.borrow()
    }

    fn init(&self) -> &Init {
        &self.initializer
    }

    // Build an MLS Credential from the supplied IdentityProvider
    fn get_credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.ident_provider.friendly_name().into()).into(),
            signature_key: self.ident_provider.public_key().as_ref().into(),
        }
    }
}

#[derive(Clone)]
pub struct InboxV2 {
    pub account: LogosAccount, // TODO: (!) don't expose account
    mls_provider: Rc<RefCell<LibcruxProvider>>,
}

impl<'a> InboxV2 {
    pub fn new() -> Self {
        let account = LogosAccount::new();
        let mls_provider = Rc::new(RefCell::new(LibcruxProvider::new().unwrap()));
        Self {
            account,
            mls_provider,
        }
    }

    pub fn register<DS: DeliveryService, RS: RegistrationService, CS: ChatStore>(
        &mut self,
        ctx: &mut ClientCtx<DS, RS, CS>,
    ) -> Result<(), ChatError> {
        let keypackage = self.create_keypackage()?;

        let bytes = keypackage.tls_serialize_detached()?;

        ctx.contact_registry()
            .register(self.account.friendly_name(), bytes)
            .map_err(ChatError::generic)?; //TODO: (P1) create an address scheme instead of using names
        Ok(())
    }

    pub fn delivery_address(&self) -> String {
        Self::delivery_address_for_account_id(&self.account.id)
    }

    pub fn id(&self) -> String {
        Self::conversation_id_for_account_id(&self.account.id)
    }

    pub fn create_group_v1<DS: DeliveryService, RS: RegistrationService, CS: ChatStore>(
        &self,
        ctx: &mut ClientCtx<DS, RS, CS>,
    ) -> Result<GroupV1Convo<MlsContext<InboxV2>>, ChatError> {
        let convo = GroupV1Convo::new(self.assemble_ctx(), ctx.ds());
        Ok(convo)
    }

    pub fn handle_frame<DS: DeliveryService, RS: RegistrationService, CS: ChatStore>(
        &self,
        ctx: &mut ClientCtx<DS, RS, CS>,
        payload_bytes: &[u8],
    ) -> Result<(), ChatError> {
        let inbox_frame = InboxV2Frame::decode(payload_bytes)?;

        let Some(payload) = inbox_frame.payload else {
            return Err(ChatError::BadParsing("InboxV2Payload missing"));
        };

        match payload {
            InviteType::GroupV1(group_v1_heavy_invite) => {
                self.handle_heavy_invite(ctx, group_v1_heavy_invite)
            }
        }
    }

    fn assemble_ctx(&self) -> MlsContext<InboxV2> {
        MlsContext {
            ident_provider: self.account.clone(),
            initializer: self.clone(),
            provider: self.mls_provider.clone(),
        }
    }

    fn persist_convo<DS: DeliveryService, RS: RegistrationService, CS: ChatStore>(
        &self,
        ctx: &'a ClientCtx<DS, RS, CS>,
        convo: impl GroupConvo<DS, RS, CS>,
    ) -> Result<(), ChatError> {
        // TODO: (P2) Remove remote_convo_id this is an implementation detail specific to PrivateV1
        // TODO: (P3) Implement From<Convo> for ConversationMeta
        let meta = ConversationMeta {
            local_convo_id: convo.id().to_string(),
            remote_convo_id: "0".into(),
            kind: storage::ConversationKind::GroupV1,
        };
        ctx.store().save_conversation(&meta)?;
        // TODO: (P1) Persist state
        Ok(())
    }

    fn handle_heavy_invite<DS: DeliveryService, RS: RegistrationService, CS: ChatStore>(
        &self,
        ctx: &mut ClientCtx<DS, RS, CS>,
        invite: GroupV1HeavyInvite,
    ) -> Result<(), ChatError> {
        let (msg_in, _rest) = MlsMessageIn::tls_deserialize_bytes(invite.welcome_bytes.as_slice())?;

        let MlsMessageBodyIn::Welcome(welcome) = msg_in.extract() else {
            return Err(ChatError::ProtocolExpectation(
                "something else",
                "Welcome".into(),
            ));
        };

        let mls_ctx = Rc::new(RefCell::new(self.assemble_ctx()));

        let convo = GroupV1Convo::new_from_welcome(mls_ctx, ctx.ds(), welcome);
        self.persist_convo(ctx, convo)
    }

    fn create_keypackage(&self) -> Result<KeyPackage, ChatError> {
        let mls_ctx = self.assemble_ctx();

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
                &*mls_ctx.provider(),
                &self.account,
                mls_ctx.get_credential(),
            )
            .expect("Failed to build KeyPackage");

        Ok(a.key_package().clone())
    }

    fn delivery_address_for_account_id(account_id: &str) -> String {
        blake2b_hex::<hash_size::AccountId>(&["InboxV2|", "delivery_address|", account_id])
    }

    fn conversation_id_for_account_id(account_id: &str) -> String {
        blake2b_hex::<hash_size::Testing>(&["InboxV2|", "conversation_id|", account_id])
    }

    pub fn load_mls_convo<DS: DeliveryService, RS: RegistrationService, CS: ChatStore>(
        &self,
        ctx: &mut ClientCtx<DS, RS, CS>,
        convo_id: String,
    ) -> Result<GroupV1Convo<MlsContext<InboxV2>>, ChatError> {
        let mls_ctx = self.assemble_ctx();

        let group_id_bytes = hex::decode(&convo_id).map_err(ChatError::generic)?;
        let group_id = GroupId::from_slice(&group_id_bytes);
        let convo =
            GroupV1Convo::load(Rc::new(RefCell::new(mls_ctx)), ctx.ds(), convo_id, group_id)?;

        Ok(convo)
    }
}

impl MlsInitializer for InboxV2 {
    fn invite_to_group_v1<DS: DeliveryService, RS: RegistrationService, CS: ChatStore>(
        &self,
        ctx: &mut ClientCtx<DS, RS, CS>,
        account_id: &str,
        welcome: &MlsMessageOut,
    ) -> Result<(), ChatError> {
        let invite = GroupV1HeavyInvite {
            welcome_bytes: welcome.to_bytes()?,
        };

        let frame = InboxV2Frame {
            payload: Some(InviteType::GroupV1(invite)),
        };

        let envelope = EnvelopeV1 {
            conversation_hint: Self::conversation_id_for_account_id(account_id),
            salt: 0,
            payload: frame.encode_to_vec().into(),
        };

        let outbound_msg = AddressedEnvelope {
            delivery_address: Self::delivery_address_for_account_id(account_id),
            data: envelope.encode_to_vec(),
        };

        ctx.ds().publish(outbound_msg).map_err(ChatError::generic)?;
        Ok(())
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
