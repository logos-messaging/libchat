mod identity;
mod mls_provider;

pub use identity::MlsIdentityProvider;

use std::cell::RefCell;
use std::rc::Rc;

use chat_proto::logoschat::envelope::EnvelopeV1;
use openmls::prelude::tls_codec::Serialize;
use openmls::prelude::*;
use prost::{Message, Oneof};
use storage::ChatStore;
use storage::ConversationKind;
use storage::ConversationMeta;

use crate::AddressedEnvelope;
use crate::ChatError;
use crate::DeliveryService;
use crate::IdentityProvider;
use crate::RegistrationService;
use crate::causal_history::CausalHistoryStore;
use crate::causal_history::MissingMessage;

// use crate::GroupConvo;
use crate::conversation::{ConversationId, GroupConvo, GroupV1Convo, Id};
use crate::outcomes::{ConversationClass, InboxOutcome, NewConversation};
use crate::types::AccountId;
use crate::utils::{blake2b_hex, hash_size};

use mls_provider::MlsEphemeralPqProvider;

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
pub struct InboxV2<IP, DS, RS, CS>
where
    IP: IdentityProvider,
{
    // Account_id field is an owned value, so it can be returned via reference.
    account_id: AccountId,
    account: Rc<RefCell<MlsIdentityProvider<IP>>>,
    ds: Rc<RefCell<DS>>,
    reg_service: Rc<RefCell<RS>>,
    store: Rc<RefCell<CS>>,
    causal: CausalHistoryStore,
    mls_provider: Rc<RefCell<MlsEphemeralPqProvider>>,
}

impl<IP, DS, CS, RS> InboxV2<IP, DS, RS, CS>
where
    IP: IdentityProvider,
    DS: DeliveryService,
    RS: RegistrationService,
    CS: ChatStore,
{
    pub fn new(
        account: IP,
        ds: Rc<RefCell<DS>>,
        reg_service: Rc<RefCell<RS>>,
        store: Rc<RefCell<CS>>,
    ) -> Self {
        let account_id = account.account_id().clone();
        let provider = MlsEphemeralPqProvider::new().unwrap();
        Self {
            account_id,
            account: Rc::new(RefCell::new(MlsIdentityProvider::new(account))),
            ds,
            reg_service,
            store,
            causal: CausalHistoryStore::new(),
            mls_provider: Rc::new(RefCell::new(provider)),
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
            .register(&*self.account.borrow(), keypackage_bytes)
            .map_err(ChatError::generic)
    }

    pub fn delivery_address(&self) -> String {
        delivery_address_for(&self.account_id)
    }

    pub fn id(&self) -> String {
        conversation_id_for(&self.account_id)
    }

    pub fn create_group_v1(
        &self,
    ) -> Result<GroupV1Convo<IP, MlsEphemeralPqProvider, DS, RS>, ChatError> {
        GroupV1Convo::new(
            self.account.clone(),
            self.mls_provider.clone(),
            self.ds.clone(),
            self.reg_service.clone(),
            self.causal.clone(),
        )
    }

    pub fn handle_frame(&self, payload_bytes: &[u8]) -> Result<InboxOutcome, ChatError> {
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
            kind: ConversationKind::GroupV1,
        };
        self.store.borrow_mut().save_conversation(&meta)?;
        // TODO: (P1) Persist state
        Ok(())
    }

    fn handle_heavy_invite(&self, invite: GroupV1HeavyInvite) -> Result<InboxOutcome, ChatError> {
        let (msg_in, _rest) = MlsMessageIn::tls_deserialize_bytes(invite.welcome_bytes.as_slice())?;

        let MlsMessageBodyIn::Welcome(welcome) = msg_in.extract() else {
            return Err(ChatError::ProtocolExpectation(
                "something else",
                "Welcome".into(),
            ));
        };

        let convo = GroupV1Convo::new_from_welcome(
            self.account.clone(),
            self.mls_provider.clone(),
            self.ds.clone(),
            self.reg_service.clone(),
            self.causal.clone(),
            welcome,
        )?;
        let convo_id: ConversationId = convo.id().to_string();
        self.persist_convo(convo)?;
        Ok(InboxOutcome {
            new_conversation: NewConversation {
                convo_id,
                class: ConversationClass::Group,
            },
            initial: None,
        })
    }

    fn create_keypackage(&self) -> Result<KeyPackage, ChatError> {
        let capabilities = Capabilities::builder()
            .ciphersuites(vec![
                Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            ])
            .extensions(vec![ExtensionType::ApplicationId])
            .build();

        let signer = self.account.borrow();
        let a = KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
            .build(
                Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
                &*self.mls_provider.borrow(),
                &*signer,
                signer.get_credential(),
            )
            .expect("Failed to build KeyPackage");

        Ok(a.key_package().clone())
    }

    pub fn load_mls_convo(
        &self,
        convo_id: String,
    ) -> Result<GroupV1Convo<IP, MlsEphemeralPqProvider, DS, RS>, ChatError> {
        let group_id_bytes = hex::decode(&convo_id).map_err(ChatError::generic)?;
        let group_id = GroupId::from_slice(&group_id_bytes);
        let convo = GroupV1Convo::load(
            self.account.clone(),
            self.mls_provider.clone(),
            self.ds.clone(),
            self.reg_service.clone(),
            self.causal.clone(),
            convo_id,
            group_id,
        )?;

        Ok(convo)
    }

    pub fn take_missing_messages(&self) -> Vec<MissingMessage> {
        self.causal.take_missing()
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
