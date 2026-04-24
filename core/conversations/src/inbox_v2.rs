use std::cell::RefCell;
use std::rc::Rc;

use chat_proto::logoschat::envelope::EnvelopeV1;
use openmls::prelude::tls_codec::Serialize;
use openmls::prelude::*;
use openmls_libcrux_crypto::Provider as LibcruxProvider;
use prost::{Message, Oneof};
use storage::ChatStore;
use storage::ConversationMeta;

use crate::AddressedEnvelope;
use crate::ChatError;
use crate::DeliveryService;
use crate::RegistrationService;
use crate::account::LogosAccount;
use crate::conversation::GroupConvo;
use crate::conversation::group_v1::MlsContext;
use crate::conversation::{GroupV1Convo, IdentityProvider};
use crate::types::AccountId;
use crate::utils::{blake2b_hex, hash_size};
pub struct PqMlsContext {
    ident_provider: LogosAccount,
    provider: LibcruxProvider,
}

impl MlsContext for PqMlsContext {
    type IDENT = LogosAccount;

    fn ident(&self) -> &LogosAccount {
        &self.ident_provider
    }

    fn provider(&self) -> &LibcruxProvider {
        &self.provider
    }

    fn invite_user<DS: DeliveryService>(
        &self,
        ds: &mut DS,
        account_id: &AccountId,
        welcome: &MlsMessageOut,
    ) -> Result<(), ChatError> {
        let invite = GroupV1HeavyInvite {
            welcome_bytes: welcome.to_bytes()?,
        };

        let frame = InboxV2Frame {
            payload: Some(InviteType::GroupV1(invite)),
        };

        let envelope = EnvelopeV1 {
            conversation_hint: ProtocolParams::conversation_id_for_account_id(&account_id),
            salt: 0,
            payload: frame.encode_to_vec().into(),
        };

        let outbound_msg = AddressedEnvelope {
            delivery_address: ProtocolParams::delivery_address_for_account_id(&account_id),
            data: envelope.encode_to_vec(),
        };

        ds.publish(outbound_msg).map_err(ChatError::generic)?;
        Ok(())
    }
}

struct InboxProtocolParams {}

impl InboxProtocolParams {
    fn delivery_address_for_account_id(account_id: &AccountId) -> String {
        blake2b_hex::<hash_size::AccountId>(&["InboxV2|", "delivery_address|", account_id.as_str()])
    }

    fn conversation_id_for_account_id(account_id: &AccountId) -> String {
        blake2b_hex::<hash_size::Testing>(&["InboxV2|", "conversation_id|", account_id.as_str()])
    }
}

type ProtocolParams = InboxProtocolParams;

pub struct InboxV2<DS, RS, CS> {
    account_id: AccountId,
    ds: Rc<RefCell<DS>>,
    reg_service: Rc<RefCell<RS>>,
    store: Rc<RefCell<CS>>,
    ctx: Rc<RefCell<PqMlsContext>>,
}

impl<'a, DS, CS, RS> InboxV2<DS, RS, CS>
where
    DS: DeliveryService,
    RS: RegistrationService,
    CS: ChatStore,
{
    pub fn new(
        account: LogosAccount,
        ds: Rc<RefCell<DS>>,
        reg_service: Rc<RefCell<RS>>,
        store: Rc<RefCell<CS>>,
    ) -> Self {
        let account_id = account.account_id().clone();
        let provider = LibcruxProvider::new().unwrap();
        Self {
            account_id,
            ds,
            reg_service,
            store,
            ctx: Rc::new(RefCell::new(PqMlsContext {
                ident_provider: account,
                provider,
            })),
        }
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Submit MlsKeypackage to registration service
    pub fn register(&mut self) -> Result<(), ChatError> {
        let keypackage_bytes = self.create_keypackage()?.tls_serialize_detached()?;

        // TODO: (P3) Each keypackage can only be used once either enable...
        // "LastResort" package or publish multiple
        self.reg_service
            .borrow_mut()
            .register(
                &self.ctx.borrow().ident_provider.friendly_name(),
                keypackage_bytes,
            )
            .map_err(ChatError::generic)
    }

    pub fn delivery_address(&self) -> String {
        ProtocolParams::delivery_address_for_account_id(&self.account_id)
    }

    pub fn id(&self) -> String {
        ProtocolParams::conversation_id_for_account_id(&self.account_id)
    }

    pub fn create_group_v1(&self) -> Result<GroupV1Convo<PqMlsContext, DS, RS>, ChatError> {
        let convo = GroupV1Convo::new(self.ctx.clone(), self.ds.clone(), self.reg_service.clone());
        Ok(convo)
    }

    pub fn handle_frame(&self, payload_bytes: &[u8]) -> Result<(), ChatError> {
        let inbox_frame = InboxV2Frame::decode(payload_bytes)?;

        let Some(payload) = inbox_frame.payload else {
            return Err(ChatError::BadParsing("InboxV2Payload missing"));
        };

        match payload {
            InviteType::GroupV1(group_v1_heavy_invite) => {
                self.handle_heavy_invite(group_v1_heavy_invite)
            }
        }
    }

    fn persist_convo(&self, convo: impl GroupConvo<DS, RS>) -> Result<(), ChatError> {
        // TODO: (P2) Remove remote_convo_id this is an implementation detail specific to PrivateV1
        // TODO: (P3) Implement From<Convo> for ConversationMeta
        let meta = ConversationMeta {
            local_convo_id: convo.id().to_string(),
            remote_convo_id: "0".into(),
            kind: storage::ConversationKind::GroupV1,
        };
        self.store.borrow_mut().save_conversation(&meta)?;
        // TODO: (P1) Persist state
        Ok(())
    }

    fn handle_heavy_invite(&self, invite: GroupV1HeavyInvite) -> Result<(), ChatError> {
        let (msg_in, _rest) = MlsMessageIn::tls_deserialize_bytes(invite.welcome_bytes.as_slice())?;

        let MlsMessageBodyIn::Welcome(welcome) = msg_in.extract() else {
            return Err(ChatError::ProtocolExpectation(
                "something else",
                "Welcome".into(),
            ));
        };

        let convo = GroupV1Convo::new_from_welcome(
            self.ctx.clone(),
            self.ds.clone(),
            self.reg_service.clone(),
            welcome,
        );
        self.persist_convo(convo)
    }

    fn create_keypackage(&self) -> Result<KeyPackage, ChatError> {
        let ctx_borrow = self.ctx.borrow();
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
                ctx_borrow.provider(),
                ctx_borrow.ident(),
                ctx_borrow.get_credential(),
            )
            .expect("Failed to build KeyPackage");

        Ok(a.key_package().clone())
    }

    pub fn load_mls_convo(
        &self,
        convo_id: String,
    ) -> Result<GroupV1Convo<PqMlsContext, DS, RS>, ChatError> {
        let group_id_bytes = hex::decode(&convo_id).map_err(ChatError::generic)?;
        let group_id = GroupId::from_slice(&group_id_bytes);
        let convo = GroupV1Convo::load(
            self.ctx.clone(),
            self.ds.clone(),
            self.reg_service.clone(),
            convo_id,
            group_id,
        )?;

        Ok(convo)
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
