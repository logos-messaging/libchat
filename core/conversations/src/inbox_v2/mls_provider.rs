use openmls::framing::MlsMessageOut;
use openmls_libcrux_crypto::CryptoProvider as LibcruxCryptoProvider;
use openmls_traits::OpenMlsProvider;
use openmls_traits::storage::{CURRENT_VERSION, StorageProvider};
use prost::Message;
use shared_traits::IdentIdRef;

use crate::{ChatError, DeliveryService};

use super::{
    AddressedEnvelope, EnvelopeV1, GroupV1HeavyInvite, InboxV2Frame, InviteType, MlsProvider,
    conversation_id_for, delivery_address_for,
};

/// Post-Quantum MLS provider: a transient view pairing the libcrux crypto/RNG
/// backend with an OpenMLS [`StorageProvider`], both borrowed. Holding borrows
/// rather than owning lets one store instance serve MLS operations while it is
/// separately owned and mutated as the chat store. Crypto/RNG are always libcrux
/// (PQ).
pub struct MlsPqProvider<'a, St: StorageProvider<CURRENT_VERSION>> {
    crypto: &'a LibcruxCryptoProvider,
    storage: &'a St,
}

impl<'a, St: StorageProvider<CURRENT_VERSION>> MlsPqProvider<'a, St> {
    pub fn new(crypto: &'a LibcruxCryptoProvider, storage: &'a St) -> Self {
        Self { crypto, storage }
    }
}

impl<St: StorageProvider<CURRENT_VERSION>> MlsProvider for MlsPqProvider<'_, St> {
    fn invite_user<DS: DeliveryService>(
        &self,
        ds: &mut DS,
        ident_id: IdentIdRef,
        welcome: &MlsMessageOut,
    ) -> Result<(), ChatError> {
        let invite = GroupV1HeavyInvite {
            welcome_bytes: welcome.to_bytes()?,
        };

        let frame = InboxV2Frame {
            payload: Some(InviteType::GroupV1(invite)),
        };

        let envelope = EnvelopeV1 {
            conversation_hint: conversation_id_for(ident_id),
            salt: 0,
            payload: frame.encode_to_vec().into(),
        };

        let outbound_msg = AddressedEnvelope {
            delivery_address: delivery_address_for(ident_id),
            data: envelope.encode_to_vec(),
        };

        ds.publish(outbound_msg).map_err(ChatError::generic)?;
        Ok(())
    }
}

impl<St: StorageProvider<CURRENT_VERSION>> OpenMlsProvider for MlsPqProvider<'_, St> {
    type CryptoProvider = LibcruxCryptoProvider;
    type RandProvider = LibcruxCryptoProvider;
    type StorageProvider = St;

    fn storage(&self) -> &Self::StorageProvider {
        self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        self.crypto
    }
}
