/// GroupV2 is a conversationType which provides effecient handling of multiple participants
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

pub struct GroupV2Convo<MP: MlsProvider> {
    mls_provider: Rc<RefCell<MP>>,
    convo_id: String,
}

impl<MP: MlsProvider> std::fmt::Debug for GroupV2Convo<MP> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupV2Convo")
            .field("convo_id", &self.convo_id)
            .finish_non_exhaustive()
    }
}

impl<MP: MlsProvider> GroupV2Convo<MP> {
    // Create a new conversation with the creator as the only participant.
    pub fn new<IP: IdentityProvider>(
        identity_provider: MlsIdentityProvider<IP>,
        mls_provider: Rc<RefCell<MP>>,
    ) -> Result<Self, ChatError> {
        // let config = Self::mls_create_config();
        // let credential = identity_provider.get_credential();

        todo!();
    }

    // Constructs a new conversation upon receiving a MlsWelcome message.
    pub fn new_from_welcome(
        mls_provider: Rc<RefCell<MP>>,
        welcome: Welcome,
    ) -> Result<Self, ChatError> {
        todo!()
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
        Self::delivery_address_from_id(convo_id)
    }

    fn ctrl_delivery_address(&self) -> String {
        Self::ctrl_delivery_address_from_id(&self.convo_id)
    }
}

impl<MP> Id for GroupV2Convo<MP>
where
    MP: MlsProvider,
{
    fn id(&self) -> ConversationIdRef<'_> {
        &self.convo_id
    }
}

impl<IP, MP, DS, RS> BaseConvo<IP, DS, RS> for GroupV2Convo<MP>
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

        todo!();
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

        todo!()
    }
}

impl<IP, MP, DS, RS> BaseGroupConvo<IP, DS, RS> for GroupV2Convo<MP>
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

        todo!();
    }
}

impl<MP: MlsProvider> GroupV2Convo<MP> {
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
