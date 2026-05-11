/// GroupV1 is a conversationType which provides effecient handling of multiple participants
/// Properties:
///     - Harvest Now Decrypt Later (HNDL) protection provided by XWING
///     - Multiple
use std::cell::RefCell;
use std::rc::Rc;

use blake2::{Blake2b, Digest, digest::consts::U6};
use chat_proto::logoschat::encryption::{EncryptedPayload, Plaintext, encrypted_payload};
use openmls::prelude::tls_codec::Deserialize;
use openmls::prelude::*;

use crate::AccountId;
use crate::conversation::{ConversationIdRef, ServiceContext};
use crate::inbox_v2::{MlsIdentityProvider, MlsProvider};
use crate::{
    AddressedEncryptedPayload, ContentData, DeliveryService, IdentityProvider, RegistrationService,
    conversation::{BaseConvo, BaseGroupConvo, ChatError, Id},
};

pub struct GroupV1Convo<MP: MlsProvider> {
    mls_provider: Rc<RefCell<MP>>,
    mls_group: MlsGroup,
    convo_id: String,
}

impl<MP: MlsProvider> std::fmt::Debug for GroupV1Convo<MP> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupV1Convo")
            .field("convo_id", &self.convo_id)
            .field("mls_epoch", &self.mls_group.epoch())
            .finish_non_exhaustive()
    }
}

impl<MP: MlsProvider> GroupV1Convo<MP> {
    // Create a new conversation with the creator as the only participant.
    pub fn new<IP: IdentityProvider>(
        identity_provider: MlsIdentityProvider<IP>,
        mls_provider: Rc<RefCell<MP>>,
    ) -> Result<Self, ChatError> {
        let config = Self::mls_create_config();
        let mls_group = {
            let credential = identity_provider.get_credential();
            MlsGroup::new(
                &*mls_provider.borrow(),
                &identity_provider,
                &config,
                credential,
            )
            .unwrap()
        };
        let convo_id = hex::encode(mls_group.group_id().as_slice());

        Ok(Self {
            mls_provider,
            mls_group,
            convo_id,
        })
    }

    // Constructs a new conversation upon receiving a MlsWelcome message.
    pub fn new_from_welcome(
        mls_provider: Rc<RefCell<MP>>,
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

        Ok(Self {
            mls_provider,
            mls_group,
            convo_id,
        })
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
}

impl<MP> Id for GroupV1Convo<MP>
where
    MP: MlsProvider,
{
    fn id(&self) -> ConversationIdRef<'_> {
        &self.convo_id
    }
}

impl<IP, MP, DS, RS> BaseConvo<IP, DS, RS> for GroupV1Convo<MP>
where
    IP: IdentityProvider,
    MP: MlsProvider,
    DS: DeliveryService,
    RS: RegistrationService,
    // KP: RegistrationService,
{
    fn init(&self, service_ctx: &mut super::ServiceContext<IP, DS, RS>) -> Result<(), ChatError> {
        // Configure the delivery service to listen for the required delivery addresses.

        service_ctx
            .ds
            .subscribe(&Self::delivery_address_from_id(&self.convo_id))
            .map_err(ChatError::generic)?;
        service_ctx
            .ds
            .subscribe(&Self::ctrl_delivery_address_from_id(&self.convo_id))
            .map_err(ChatError::generic)?;

        Ok(())
    }

    fn send_content(
        &mut self,
        service_ctx: &mut super::ServiceContext<IP, DS, RS>,
        content: &[u8],
    ) -> Result<(), ChatError> {
        let signer = MlsIdentityProvider(&service_ctx.identity_provider);
        let mls_message_out = self
            .mls_group
            .create_message(&*self.mls_provider.borrow(), &signer, content)
            .unwrap();

        let payload = AddressedEncryptedPayload {
            delivery_address: self.delivery_address(),
            data: EncryptedPayload {
                encryption: Some(encrypted_payload::Encryption::Plaintext(Plaintext {
                    payload: mls_message_out.to_bytes().unwrap().into(),
                })),
            },
        };

        let env = payload.into_envelope(self.id().into());
        service_ctx
            .ds
            .publish(env)
            .map_err(|e| ChatError::Delivery(e.to_string()))?;

        Ok(())
    }

    fn handle_frame(
        &mut self,
        _service_ctx: &mut super::ServiceContext<IP, DS, RS>,
        encoded_payload: EncryptedPayload,
    ) -> Result<Option<ContentData>, ChatError> {
        let bytes = match encoded_payload.encryption {
            Some(encrypted_payload::Encryption::Plaintext(pt)) => pt.payload,
            _ => {
                return Err(ChatError::generic("Expected plaintext"));
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
            return Ok(None);
        }

        let processed = self
            .mls_group
            .process_message(provider, protocol_message)
            .map_err(ChatError::generic)?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(msg) => Ok(Some(ContentData {
                conversation_id: hex::encode(self.mls_group.group_id().as_slice()),
                data: msg.into_bytes(),
                is_new_convo: false,
            })),
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                self.mls_group
                    .merge_staged_commit(provider, *commit)
                    .map_err(ChatError::generic)?;
                Ok(None)
            }
            _ => {
                // TODO: (P2) Log unknown message type
                Ok(None)
            }
        }
    }
}

impl<IP, MP, DS, RS> BaseGroupConvo<IP, DS, RS> for GroupV1Convo<MP>
where
    IP: IdentityProvider,
    MP: MlsProvider,
    DS: DeliveryService,
    RS: RegistrationService,
{
    // add_members returns:
    //   commit      — the Commit message Alice broadcasts to all members
    //   welcome     — the Welcome message sent privately to each new joiner
    //   _group_info — used for external joins; ignore for now
    fn add_member(
        &mut self,
        service_ctx: &mut ServiceContext<IP, DS, RS>,
        members: &[&AccountId],
    ) -> Result<(), ChatError> {
        let mls_provider = &*self.mls_provider.borrow();

        if members.len() > 50 {
            // This is a temporary limit that originates from the the De-MLS epoch time.
            return Err(ChatError::generic(
                "Cannot add more than 50 Members at a time",
            ));
        }

        if members.is_empty() {
            return Ok(());
        }

        // Get the Keypacakages and transpose any errors.
        // The account_id is kept so invites can be addressed properly
        let keypkgs = members
            .iter()
            .map(|ident| self.key_package_for_account(service_ctx, ident))
            .collect::<Result<Vec<_>, ChatError>>()?;

        let signer = MlsIdentityProvider(&service_ctx.identity_provider);
        let (commit, welcome, _group_info) = self
            .mls_group
            .add_members(mls_provider, &signer, keypkgs.iter().as_slice())
            .unwrap();

        self.mls_group.merge_pending_commit(mls_provider).unwrap();

        // TODO: (P3) Evaluate privacy/performance implications of an aggregated Welcome for multiple users
        for account_id in members {
            self.mls_provider
                .borrow()
                .invite_user(&mut service_ctx.ds, account_id, &welcome)?;
        }

        let encrypted_payload = EncryptedPayload {
            encryption: Some(encrypted_payload::Encryption::Plaintext(Plaintext {
                payload: commit.to_bytes().map_err(ChatError::generic)?.into(),
            })),
        };

        let addr_enc_payload = AddressedEncryptedPayload {
            delivery_address: self.ctrl_delivery_address(),
            data: encrypted_payload,
        };
        // Prepare commit message
        // TODO: (P1) Make GroupConvos agnostic to framing so its less error prone and more
        let env = addr_enc_payload.into_envelope(self.convo_id.clone());

        service_ctx
            .ds
            .publish(env)
            .map_err(|e| ChatError::Generic(format!("Publish: {e}")))
    }
}

impl<MP: MlsProvider> GroupV1Convo<MP> {
    fn key_package_for_account<
        IP: IdentityProvider,
        DS: DeliveryService,
        RS: RegistrationService,
    >(
        &self,
        service_ctx: &mut ServiceContext<IP, DS, RS>,
        ident: &AccountId,
    ) -> Result<KeyPackage, ChatError> {
        let retrieved_bytes = service_ctx
            .rs
            .retrieve(ident)
            .map_err(|e: RS::Error| ChatError::Generic(e.to_string()))?;

        // dbg!(ctx.contact_registry());
        let Some(keypkg_bytes) = retrieved_bytes else {
            return Err(ChatError::generic("Group Contact Not Found"));
        };

        let key_package_in = KeyPackageIn::tls_deserialize(&mut keypkg_bytes.as_slice())?;
        let keypkg = key_package_in
            .validate(self.mls_provider.borrow().crypto(), ProtocolVersion::Mls10)
            .map_err(ChatError::generic)?; //TODO: P3 - Hardcoded Protocol Version
        Ok(keypkg)
    }
}
