/// GroupV1 is a conversationType which provides effecient handling of multiple participants
/// Properties:
///     - Harvest Now Decrypt Later (HNDL) protection provided by XWING
///     - Multiple
use std::cell::RefCell;
use std::rc::Rc;

use blake2::{Blake2b, Digest, digest::consts::U6};
use chat_proto::logoschat::encryption::{EncryptedPayload, Plaintext, encrypted_payload};
use chat_proto::logoschat::reliability::ReliablePayload;
use crypto::Ed25519VerifyingKey;
use openmls::prelude::tls_codec::Deserialize;
use openmls::prelude::*;
use openmls_libcrux_crypto::Provider as LibcruxProvider;
use openmls_traits::signatures::Signer as OpenMlsSigner;
use prost::Message as _;
use storage::ConversationKind;

use crate::causal_history::CausalHistoryStore;
use crate::types::AccountId;
use crate::{
    DeliveryService,
    conversation::{ChatError, Convo, GroupConvo, Id},
    outcomes::{Content, ConvoOutcome},
    service_traits::KeyPackageProvider,
    types::AddressedEncryptedPayload,
};

/// Provides the identity information needed to participate in an MLS group.
///
/// Implementors must also implement [`OpenMlsSigner`] so they can sign MLS
/// messages. The two methods here supply what [`MlsContext::get_credential`]
/// needs to build a [`CredentialWithKey`]: `friendly_name` becomes the
/// `BasicCredential` label and `public_key` becomes the signature-verification key.
pub trait IdentityProvider: OpenMlsSigner {
    fn friendly_name(&self) -> String;
    fn public_key(&self) -> &Ed25519VerifyingKey;
}

/// Connects the MLS protocol engine to app-level identity and transport.
///
/// `GroupV1Convo` is generic over this trait so the MLS logic stays
/// independent of how identities are stored or how invites are delivered.
/// Implementors supply:
/// - a [`LibcruxProvider`] for MLS crypto operations
/// - an [`IdentityProvider`] for signing and credential construction
/// - [`invite_user`] — the app-specific logic for routing a [`Welcome`]
///   message to a new member's inbox
pub trait MlsContext {
    type IDENT: IdentityProvider;

    fn ident(&self) -> &Self::IDENT;
    fn provider(&self) -> &LibcruxProvider;

    // Build an MLS Credential from the supplied IdentityProvider
    fn get_credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.ident().friendly_name().into()).into(),
            signature_key: self.ident().public_key().as_ref().into(),
        }
    }

    fn invite_user<DS: DeliveryService>(
        &self,
        ds: &mut DS,
        account_id: &AccountId,
        welcome: &MlsMessageOut,
    ) -> Result<(), ChatError>;
}

pub struct GroupV1Convo<MlsCtx, DS, KP> {
    ctx: Rc<RefCell<MlsCtx>>,
    account_id: AccountId,
    ds: Rc<RefCell<DS>>,
    keypkg_provider: Rc<RefCell<KP>>,
    mls_group: MlsGroup,
    convo_id: String,
    causal: CausalHistoryStore,
}

impl<MlsCtx, DS, KP> std::fmt::Debug for GroupV1Convo<MlsCtx, DS, KP>
where
    MlsCtx: MlsContext,
    DS: DeliveryService,
    KP: KeyPackageProvider,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupV1Convo")
            .field("name", &self.ctx.borrow().ident().friendly_name())
            .field("convo_id", &self.convo_id)
            .field("mls_epoch", &self.mls_group.epoch())
            .finish_non_exhaustive()
    }
}

impl<MlsCtx, DS, KP> GroupV1Convo<MlsCtx, DS, KP>
where
    MlsCtx: MlsContext,
    DS: DeliveryService,
    KP: KeyPackageProvider,
{
    // Create a new conversation with the creator as the only participant.
    pub fn new(
        ctx: Rc<RefCell<MlsCtx>>,
        account_id: AccountId,
        ds: Rc<RefCell<DS>>,
        keypkg_provider: Rc<RefCell<KP>>,
        causal: CausalHistoryStore,
    ) -> Result<Self, ChatError> {
        let config = Self::mls_create_config();
        let mls_group = {
            let ctx_ref = ctx.borrow();
            MlsGroup::new(
                ctx_ref.provider(),
                ctx_ref.ident(),
                &config,
                ctx_ref.get_credential(),
            )
            .unwrap()
        };
        let convo_id = hex::encode(mls_group.group_id().as_slice());
        Self::subscribe(&mut ds.borrow_mut(), &convo_id)?;

        Ok(Self {
            ctx,
            account_id,
            ds,
            keypkg_provider,
            mls_group,
            convo_id,
            causal,
        })
    }

    // Constructs a new conversation upon receiving a MlsWelcome message.
    pub fn new_from_welcome(
        ctx: Rc<RefCell<MlsCtx>>,
        account_id: AccountId,
        ds: Rc<RefCell<DS>>,
        keypkg_provider: Rc<RefCell<KP>>,
        causal: CausalHistoryStore,
        welcome: Welcome,
    ) -> Result<Self, ChatError> {
        let mls_group = {
            let ctx_borrow = ctx.borrow();
            let provider = ctx_borrow.provider();

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
            ctx,
            account_id,
            ds,
            keypkg_provider,
            mls_group,
            convo_id,
            causal,
        })
    }

    pub fn load(
        ctx: Rc<RefCell<MlsCtx>>,
        account_id: AccountId,
        ds: Rc<RefCell<DS>>,
        keypkg_provider: Rc<RefCell<KP>>,
        causal: CausalHistoryStore,
        convo_id: String,
        group_id: GroupId,
    ) -> Result<Self, ChatError> {
        let mls_group = MlsGroup::load(ctx.borrow().provider().storage(), &group_id)
            .map_err(ChatError::generic)?
            .ok_or_else(|| ChatError::NoConvo("mls group not found".into()))?;

        Self::subscribe(&mut *ds.borrow_mut(), &convo_id)?;

        Ok(GroupV1Convo {
            ctx,
            account_id,
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
        let keypkg = key_package_in.validate(
            self.ctx.borrow().provider().crypto(),
            ProtocolVersion::Mls10,
        )?; //TODO: P3 - Hardcoded Protocol Version
        Ok(keypkg)
    }
}

impl<MlsCtx, DS, KP> Id for GroupV1Convo<MlsCtx, DS, KP>
where
    MlsCtx: MlsContext,
    DS: DeliveryService,
    KP: KeyPackageProvider,
{
    fn id(&self) -> &str {
        &self.convo_id
    }
}

impl<MlsCtx, DS, KP> Convo for GroupV1Convo<MlsCtx, DS, KP>
where
    MlsCtx: MlsContext,
    DS: DeliveryService,
    KP: KeyPackageProvider,
{
    fn send_message(
        &mut self,
        content: &[u8],
    ) -> Result<Vec<AddressedEncryptedPayload>, ChatError> {
        let ctx_ref = self.ctx.borrow();
        let provider = ctx_ref.provider();

        let sender_id = self.account_id.as_str();
        let reliable = self.causal.on_send(&self.convo_id, sender_id, content);
        let wire = reliable.encode_to_vec();

        let mls_message_out = self
            .mls_group
            .create_message(provider, ctx_ref.ident(), &wire)
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

        let ctx_borrow = self.ctx.borrow();
        let provider = ctx_borrow.provider();

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
                self.causal.on_receive(&self.convo_id, &reliable)?;
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

impl<MlsCtx, DS, KP> GroupConvo<DS, KP> for GroupV1Convo<MlsCtx, DS, KP>
where
    MlsCtx: MlsContext,
    DS: DeliveryService,
    KP: KeyPackageProvider,
{
    // add_members returns:
    //   commit      — the Commit message Alice broadcasts to all members
    //   welcome     — the Welcome message sent privately to each new joiner
    //   _group_info — used for external joins; ignore for now
    fn add_member(&mut self, members: &[&AccountId]) -> Result<(), ChatError> {
        let ctx_ref = self.ctx.borrow();
        let provider = ctx_ref.provider();

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
            .add_members(provider, ctx_ref.ident(), keypkgs.iter().as_slice())
            .unwrap();

        self.mls_group.merge_pending_commit(provider).unwrap();

        // TODO: (P3) Evaluate privacy/performance implications of an aggregated Welcome for multiple users
        for account_id in members {
            ctx_ref.invite_user(&mut *self.ds.borrow_mut(), account_id, &welcome)?;
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
