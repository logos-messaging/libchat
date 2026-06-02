/// GroupV1 is a conversationType which provides effecient handling of multiple participants
/// Properties:
///     - Harvest Now Decrypt Later (HNDL) protection provided by XWING
///     - Multiple
use std::cell::RefCell;
use std::rc::Rc;

use blake2::{Blake2b, Digest, digest::consts::U6};
use chat_proto::logoschat::encryption::{EncryptedPayload, Plaintext, encrypted_payload};
use chat_proto::logoschat::reliability::ReliablePayload;
use openmls::prelude::tls_codec::Deserialize;
use openmls::prelude::*;
use prost::Message;
use storage::ConversationKind;

use crate::IdentityProvider;
use crate::causal_history::CausalHistoryStore;
use crate::inbox_v2::{MlsIdentityProvider, MlsProvider};
use crate::types::AccountId;
use crate::{
    DeliveryService,
    conversation::{ChatError, Convo, GroupConvo, Id},
    outcomes::{Content, ConvoOutcome},
    service_traits::KeyPackageProvider,
    types::AddressedEncryptedPayload,
};

pub struct GroupV1Convo<IP: IdentityProvider, MP, DS, KP> {
    identity_provider: Rc<RefCell<MlsIdentityProvider<IP>>>,
    mls_provider: Rc<RefCell<MP>>,
    ds: Rc<RefCell<DS>>,
    keypkg_provider: Rc<RefCell<KP>>,
    mls_group: MlsGroup,
    convo_id: String,
    causal: CausalHistoryStore,
}

impl<IP, MP, DS, KP> std::fmt::Debug for GroupV1Convo<IP, MP, DS, KP>
where
    IP: IdentityProvider,
    MP: MlsProvider,
    DS: DeliveryService,
    KP: KeyPackageProvider,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupV1Convo")
            .field("name", &self.identity_provider.borrow().display_name())
            .field("convo_id", &self.convo_id)
            .field("mls_epoch", &self.mls_group.epoch())
            .finish_non_exhaustive()
    }
}

impl<IP, MP, DS, KP> GroupV1Convo<IP, MP, DS, KP>
where
    IP: IdentityProvider,
    MP: MlsProvider,
    DS: DeliveryService,
    KP: KeyPackageProvider,
{
    // Create a new conversation with the creator as the only participant.
    pub fn new(
        identity_provider: Rc<RefCell<MlsIdentityProvider<IP>>>,
        mls_provider: Rc<RefCell<MP>>,
        ds: Rc<RefCell<DS>>,
        keypkg_provider: Rc<RefCell<KP>>,
        causal: CausalHistoryStore,
    ) -> Result<Self, ChatError> {
        let config = Self::mls_create_config();
        let mls_group = {
            let mls_provider_ref = mls_provider.borrow();
            let signer = identity_provider.borrow();
            let credential = signer.get_credential();

            MlsGroup::new(&*mls_provider_ref, &*signer, &config, credential).unwrap()
        };
        let convo_id = hex::encode(mls_group.group_id().as_slice());
        Self::subscribe(&mut ds.borrow_mut(), &convo_id)?;

        Ok(Self {
            identity_provider,
            mls_provider,
            ds,
            keypkg_provider,
            mls_group,
            convo_id,
            causal,
        })
    }

    // Constructs a new conversation upon receiving a MlsWelcome message.
    pub fn new_from_welcome(
        identity_provider: Rc<RefCell<MlsIdentityProvider<IP>>>,
        mls_provider: Rc<RefCell<MP>>,
        ds: Rc<RefCell<DS>>,
        keypkg_provider: Rc<RefCell<KP>>,
        causal: CausalHistoryStore,
        welcome: Welcome,
    ) -> Result<Self, ChatError> {
        let mls_group = {
            let provider = &*mls_provider.borrow();
            StagedWelcome::build_from_welcome(provider, &Self::mls_join_config(), welcome)
                .unwrap()
                .build()
                .unwrap()
                .into_group(provider)
                .unwrap()
        };

        let convo_id = hex::encode(mls_group.group_id().as_slice());
        Self::subscribe(&mut *ds.borrow_mut(), &convo_id)?;

        Ok(Self {
            identity_provider,
            mls_provider,
            ds,
            keypkg_provider,
            mls_group,
            convo_id,
            causal,
        })
    }

    pub fn load(
        identity_provider: Rc<RefCell<MlsIdentityProvider<IP>>>,
        mls_provider: Rc<RefCell<MP>>,
        ds: Rc<RefCell<DS>>,
        keypkg_provider: Rc<RefCell<KP>>,
        causal: CausalHistoryStore,
        convo_id: String,
        group_id: GroupId,
    ) -> Result<Self, ChatError> {
        let mls_group = MlsGroup::load(mls_provider.borrow().storage(), &group_id)
            .map_err(ChatError::generic)?
            .ok_or_else(|| ChatError::NoConvo("mls group not found".into()))?;

        Self::subscribe(&mut *ds.borrow_mut(), &convo_id)?;

        Ok(GroupV1Convo {
            identity_provider,
            mls_provider,
            ds,
            keypkg_provider,
            mls_group,
            convo_id,
            causal,
        })
    }

    // Configure the delivery service to listen for the required delivery addresses.
    fn subscribe(ds: &mut DS, convo_id: &str) -> Result<(), ChatError> {
        ds.subscribe(&Self::delivery_address_from_id(convo_id))
            .map_err(ChatError::generic)?;
        ds.subscribe(&Self::ctrl_delivery_address_from_id(convo_id))
            .map_err(ChatError::generic)?;

        Ok(())
    }

    fn mls_create_config() -> MlsGroupCreateConfig {
        MlsGroupCreateConfig::builder()
            .ciphersuite(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)
            .use_ratchet_tree_extension(true) // This is handy for now, until there is central store for this data
            .build()
    }

    fn mls_join_config() -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder().build()
    }

    fn delivery_address_from_id(convo_id: &str) -> String {
        let hash = Blake2b::<U6>::new()
            .chain_update("delivery_addr|")
            .chain_update(convo_id)
            .finalize();
        hex::encode(hash)
    }

    fn delivery_address(&self) -> String {
        Self::delivery_address_from_id(&self.convo_id)
    }

    fn ctrl_delivery_address_from_id(convo_id: &str) -> String {
        let hash = Blake2b::<U6>::new()
            .chain_update("ctrl_delivery_addr|")
            .chain_update(convo_id)
            .finalize();
        hex::encode(hash)
    }

    fn ctrl_delivery_address(&self) -> String {
        Self::ctrl_delivery_address_from_id(&self.convo_id)
    }

    fn key_package_for_account(&self, ident: &AccountId) -> Result<KeyPackage, ChatError> {
        let retrieved_bytes = self
            .keypkg_provider
            .borrow()
            .retrieve(ident)
            .map_err(|e: KP::Error| ChatError::Generic(e.to_string()))?;

        // dbg!(ctx.contact_registry());
        let Some(keypkg_bytes) = retrieved_bytes else {
            return Err(ChatError::Protocol("Contact Not Found".into()));
        };

        let key_package_in = KeyPackageIn::tls_deserialize(&mut keypkg_bytes.as_slice())?;
        let keypkg =
            key_package_in.validate(self.mls_provider.borrow().crypto(), ProtocolVersion::Mls10)?; //TODO: P3 - Hardcoded Protocol Version
        Ok(keypkg)
    }
}

impl<IP, MP, DS, KP> Id for GroupV1Convo<IP, MP, DS, KP>
where
    IP: IdentityProvider,
    MP: MlsProvider,
    DS: DeliveryService,
    KP: KeyPackageProvider,
{
    fn id(&self) -> &str {
        &self.convo_id
    }
}

impl<IP, MP, DS, KP> Convo for GroupV1Convo<IP, MP, DS, KP>
where
    IP: IdentityProvider,
    MP: MlsProvider,
    DS: DeliveryService,
    KP: KeyPackageProvider,
{
    fn send_message(
        &mut self,
        content: &[u8],
    ) -> Result<Vec<AddressedEncryptedPayload>, ChatError> {
        let sender_id = self.identity_provider.borrow();
        let reliable =
            self.causal
                .on_send(&self.convo_id, sender_id.account_id().as_str(), content);
        let wire = reliable.encode_to_vec();

        let mls_message_out = self
            .mls_group
            .create_message(
                &*self.mls_provider.borrow(),
                &*self.identity_provider.borrow(),
                &wire,
            )
            .unwrap();

        let a = AddressedEncryptedPayload {
            delivery_address: self.delivery_address(),
            data: EncryptedPayload {
                encryption: Some(encrypted_payload::Encryption::Plaintext(Plaintext {
                    payload: mls_message_out.to_bytes().unwrap().into(),
                })),
            },
        };

        Ok(vec![a])
    }

    fn handle_frame(
        &mut self,
        encoded_payload: EncryptedPayload,
    ) -> Result<ConvoOutcome, ChatError> {
        let bytes = match encoded_payload.encryption {
            Some(encrypted_payload::Encryption::Plaintext(pt)) => pt.payload,
            _ => {
                return Err(ChatError::ProtocolExpectation(
                    "None",
                    "Some(Encryption::Plaintext)".into(),
                ));
            }
        };

        let mls_message =
            MlsMessageIn::tls_deserialize_exact_bytes(&bytes).map_err(ChatError::generic)?;

        let protocol_message: ProtocolMessage = mls_message
            .try_into_protocol_message()
            .map_err(ChatError::generic)?;

        let provider = &*self.mls_provider.borrow();

        if protocol_message.epoch() < self.mls_group.epoch() {
            // TODO: (P1) Add logging for messages arriving from past epoch.
            return Ok(ConvoOutcome::empty(self.id().to_string()));
        }

        let processed = self
            .mls_group
            .process_message(provider, protocol_message)
            .map_err(ChatError::generic)?;

        let content = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(msg) => {
                let reliable = ReliablePayload::decode(msg.into_bytes().as_slice())?;
                self.causal.on_receive(&self.convo_id, &reliable);
                Some(Content {
                    bytes: reliable.content.to_vec(),
                })
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                self.mls_group
                    .merge_staged_commit(provider, *commit)
                    .map_err(ChatError::generic)?;
                None
            }
            _ => {
                // TODO: (P2) Log unknown message type
                None
            }
        };
        Ok(ConvoOutcome {
            convo_id: self.id().to_string(),
            content,
        })
    }

    fn remote_id(&self) -> String {
        // "group_remote_id".into()
        todo!()
    }

    fn convo_type(&self) -> storage::ConversationKind {
        ConversationKind::GroupV1
    }
}

impl<IP, MP, DS, KP> GroupConvo<DS, KP> for GroupV1Convo<IP, MP, DS, KP>
where
    IP: IdentityProvider,
    MP: MlsProvider,
    DS: DeliveryService,
    KP: KeyPackageProvider,
{
    // add_members returns:
    //   commit      — the Commit message Alice broadcasts to all members
    //   welcome     — the Welcome message sent privately to each new joiner
    //   _group_info — used for external joins; ignore for now
    fn add_member(&mut self, members: &[&AccountId]) -> Result<(), ChatError> {
        let identity_provider = &*self.identity_provider.borrow();
        let mls_provider = &*self.mls_provider.borrow();

        if members.len() > 50 {
            // This is a temporary limit that originates from the the De-MLS epoch time.
            return Err(ChatError::Protocol(
                "Cannot add more than 50 Members at a time".into(),
            ));
        }

        // Get the Keypacakages and transpose any errors.
        // The account_id is kept so invites can be addressed properly
        let keypkgs = members
            .iter()
            .map(|ident| self.key_package_for_account(ident))
            .collect::<Result<Vec<_>, ChatError>>()?;

        let (commit, welcome, _group_info) = self
            .mls_group
            .add_members(mls_provider, identity_provider, keypkgs.iter().as_slice())
            .unwrap();

        self.mls_group.merge_pending_commit(mls_provider).unwrap();

        // TODO: (P3) Evaluate privacy/performance implications of an aggregated Welcome for multiple users
        for account_id in members {
            self.mls_provider.borrow().invite_user(
                &mut *self.ds.borrow_mut(),
                account_id,
                &welcome,
            )?;
        }

        let encrypted_payload = EncryptedPayload {
            encryption: Some(encrypted_payload::Encryption::Plaintext(Plaintext {
                payload: commit.to_bytes()?.into(),
            })),
        };

        let addr_enc_payload = AddressedEncryptedPayload {
            delivery_address: self.ctrl_delivery_address(),
            data: encrypted_payload,
        };
        // Prepare commit message
        // TODO: (P1) Make GroupConvos agnostic to framing so its less error prone and more
        let env = addr_enc_payload.into_envelope(self.convo_id.clone());

        self.ds
            .borrow_mut()
            .publish(env)
            .map_err(|e| ChatError::Generic(format!("Publish: {e}")))
    }

    fn send_content(&mut self, content: &[u8]) -> Result<(), ChatError> {
        let payloads = self.send_message(content)?;
        for payload in payloads {
            self.ds
                .borrow_mut()
                .publish(payload.into_envelope(self.id().into()))
                .map_err(|e| ChatError::Delivery(e.to_string()))?;
        }
        Ok(())
    }
}
