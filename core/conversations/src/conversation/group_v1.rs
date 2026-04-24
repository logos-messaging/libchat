use std::cell::{Ref, RefCell};
use std::rc::Rc;

use blake2::{Blake2b, Digest, digest::consts::U6};
use crypto::Ed25519VerifyingKey;
use openmls::prelude::tls_codec::Deserialize;
use openmls::prelude::*;
use openmls_libcrux_crypto::Provider as LibcruxProvider;

use openmls_traits::signatures::Signer as OpenMlsSigner;

use crate::{
    DeliveryService, RegistrationService,
    conversation::{ChatError, ConversationId, Convo, GroupConvo, Id},
    ctx::ClientCtx,
    types::{AddressedEncryptedPayload, ContentData},
};
use chat_proto::logoschat::encryption::{EncryptedPayload, Plaintext, encrypted_payload};
use storage::{ChatStore, ConversationKind};

pub trait IdentityProvider: OpenMlsSigner {
    fn friendly_name(&self) -> String;
    fn public_key(&self) -> Ed25519VerifyingKey;
    // fn installation_key() -> u8;
}

pub trait MlsInitializer {
    fn invite_to_group_v1<DS: DeliveryService, RS: RegistrationService, CS: ChatStore>(
        &self,
        ctx: &mut ClientCtx<DS, RS, CS>,
        account_id: &str,
        welcome: &MlsMessageOut,
        // ratchet_tree: RatchetTree, // Embedded
    ) -> Result<(), ChatError>;
}

pub trait MlsCtx {
    type IDENT: IdentityProvider;
    type INIT: MlsInitializer;

    fn ident(&self) -> &Self::IDENT;
    fn provider(&self) -> Ref<'_, LibcruxProvider>;
    fn init(&self) -> &Self::INIT;

    // Build an MLS Credential from the supplied IdentityProvider
    fn get_credential(&self) -> CredentialWithKey;
}

pub struct GroupV1Convo<Ctx: MlsCtx> {
    ctx: Rc<RefCell<Ctx>>,
    pub(crate) mls_group: MlsGroup, // TODO: (!) Fix Visibility
    convo_id: String,
}

impl<Ctx: MlsCtx> std::fmt::Debug for GroupV1Convo<Ctx> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupV1Convo")
            .field("name", &self.ctx.borrow().ident().friendly_name())
            .field("convo_id", &self.convo_id)
            .field("mls_epoch", &self.mls_group.epoch())
            .finish_non_exhaustive()
    }
}

impl<Ctx: MlsCtx> GroupV1Convo<Ctx> {
    pub fn new<DS: DeliveryService>(ctx: Ctx, ds: &mut DS) -> Self {
        let config = Self::mls_create_config();
        let ctx = Rc::new(RefCell::new(ctx));
        let mls_group = {
            let ctx_ref = ctx.borrow();
            MlsGroup::new(
                &*ctx_ref.provider(),
                ctx_ref.ident(),
                &config,
                ctx_ref.get_credential(),
            )
            .unwrap()
        };
        let convo_id = hex::encode(mls_group.group_id().as_slice());
        Self::subscribe(ds, &convo_id);

        println!(
            "@   Create Convo: {}.  {}.  d:{}  dc:{}",
            ctx.borrow().ident().friendly_name(),
            convo_id,
            Self::delivery_address_from_id(&convo_id),
            Self::ctrl_delivery_address_from_id(&convo_id)
        );
        Self {
            ctx,
            mls_group,
            convo_id,
        }
    }

    pub fn new_from_welcome<DS: DeliveryService>(
        ctx: Rc<RefCell<Ctx>>,
        ds: &mut DS,
        welcome: Welcome,
    ) -> Self {
        let mls_group = {
            let ctx_borrow = ctx.borrow();
            let provider = ctx_borrow.provider();

            StagedWelcome::build_from_welcome(&*provider, &Self::mls_join_config(), welcome)
                .unwrap()
                .build()
                .unwrap()
                .into_group(&*provider)
                .unwrap()
        };

        let convo_id = hex::encode(mls_group.group_id().as_slice());
        Self::subscribe(ds, &convo_id);

        println!(
            "@   Welcome Convo: I:{}.  {}.  d:{}  dc:{}",
            ctx.borrow().ident().friendly_name(),
            convo_id,
            Self::delivery_address_from_id(&convo_id),
            Self::ctrl_delivery_address_from_id(&convo_id)
        );

        GroupV1Convo {
            ctx,
            mls_group,
            convo_id,
        }
    }

    pub fn load<DS: DeliveryService>(
        ctx: Rc<RefCell<Ctx>>,
        ds: &mut DS,
        convo_id: String,
        group_id: GroupId,
    ) -> Result<Self, ChatError> {
        let Some(mls_group) = MlsGroup::load(ctx.borrow().provider().storage(), &group_id)
            .map_err(ChatError::generic)?
        else {
            return Err(ChatError::NoConvo("mls group not found".into()));
        };

        Self::subscribe(ds, &convo_id)?;

        Ok(GroupV1Convo {
            ctx,
            mls_group,
            convo_id,
        })
    }

    fn subscribe<DS: DeliveryService>(ds: &mut DS, convo_id: &str) -> Result<(), ChatError> {
        ds.subscribe(Self::delivery_address_from_id(&convo_id))
            .map_err(ChatError::generic)?;
        ds.subscribe(Self::ctrl_delivery_address_from_id(&convo_id))
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

    fn key_package_for_account<DS: DeliveryService, RS: RegistrationService, CS: ChatStore>(
        &self,
        ctx: &mut ClientCtx<DS, RS, CS>,
        ident: &str,
    ) -> Result<KeyPackage, ChatError> {
        let retrieved_bytes = ctx
            .contact_registry()
            .retreive(ident)
            .map_err(|e| ChatError::Generic(e.to_string()))?;

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

impl<Ctx: MlsCtx> Id for GroupV1Convo<Ctx> {
    fn id(&self) -> ConversationId<'_> {
        &self.convo_id
    }
}

impl<Ctx: MlsCtx> Convo for GroupV1Convo<Ctx> {
    fn send_message(
        &mut self,
        content: &[u8],
    ) -> Result<Vec<AddressedEncryptedPayload>, ChatError> {
        let ctx_ref = self.ctx.borrow();
        let provider = ctx_ref.provider();
        let mls_message_out = self
            .mls_group
            .create_message(&*provider, ctx_ref.ident(), content)
            .unwrap();

        let a = AddressedEncryptedPayload {
            delivery_address: self.delivery_address(),
            data: EncryptedPayload {
                encryption: Some(
                    chat_proto::logoschat::encryption::encrypted_payload::Encryption::Plaintext(
                        Plaintext {
                            payload: mls_message_out.to_bytes().unwrap().into(),
                        },
                    ),
                ),
            },
        };

        Ok(vec![a])
    }

    fn handle_frame(
        &mut self,
        encoded_payload: EncryptedPayload,
    ) -> Result<Option<ContentData>, ChatError> {
        use chat_proto::logoschat::encryption::encrypted_payload::Encryption;

        let bytes = match encoded_payload.encryption {
            Some(Encryption::Plaintext(pt)) => pt.payload,
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
            // TODO: (!) Determine how to handle messages for old epochs. Minimally log this.
            return Ok(None);
        }

        let processed = self
            .mls_group
            .process_message(&*provider, protocol_message)
            .map_err(ChatError::generic)?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(msg) => Ok(Some(ContentData {
                conversation_id: hex::encode(self.mls_group.group_id().as_slice()),
                data: msg.into_bytes(),
                is_new_convo: false,
            })),
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                self.mls_group
                    .merge_staged_commit(&*provider, *commit)
                    .map_err(ChatError::generic)?;
                Ok(None)
            }
            x => {
                println!("Unhabled Message ttype {:?}", x);
                Ok(None)
            }
        }
    }

    fn remote_id(&self) -> String {
        // "group_remote_id".into()
        todo!()
    }

    fn convo_type(&self) -> storage::ConversationKind {
        ConversationKind::GroupV1
    }
}

impl<Ctx: MlsCtx, DS: DeliveryService, RS: RegistrationService, CS: ChatStore>
    GroupConvo<DS, RS, CS> for GroupV1Convo<Ctx>
{
    fn add_member(
        &mut self,
        ctx: &mut ClientCtx<DS, RS, CS>,
        members: &[&str],
    ) -> Result<(), ChatError> {
        // add_members returns:
        //   commit      — the Commit message Alice broadcasts to all members
        //   welcome     — the Welcome message sent privately to each new joiner
        //   _group_info — used for external joins; ignore for now
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
            // .map(|ident| self.key_package_for_account(ctx, ident))
            .map(|ident| self.key_package_for_account(ctx, ident))
            .collect::<Result<Vec<_>, ChatError>>()?;

        let (commit, welcome, _group_info) = self
            .mls_group
            .add_members(&*provider, ctx_ref.ident(), keypkgs.iter().as_slice())
            .unwrap();

        self.mls_group.merge_pending_commit(&*provider).unwrap();

        // TODO: (P3) Evaluate privacy/performance implications of an aggregated Welcome for multiple users
        for account_id in members {
            ctx_ref
                .init()
                .invite_to_group_v1(ctx, account_id, &welcome)?;
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

        ctx.ds()
            .publish(env)
            .map_err(|e| ChatError::Generic(format!("Publish: {e}")))
    }
}
