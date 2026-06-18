/// Service traits define the functionality which must be externally supplied by
/// platform clients. Platforms can alter the behaviour of the chat core by supplying
/// different implementations.
use shared_traits::IdentityProvider;
use std::{
    fmt::{Debug, Display},
    time::Duration,
};

use crate::{AccountService, ConversationId, types::AddressedEnvelope};

/// A Delivery service is responsible for payload transport.
/// This interface allows Conversations to send payloads on the wire as well as
/// register interest in delivery_addresses. Client implementations are responsible
/// for providing the inbound payloads to Core::handle_payload.
pub trait DeliveryService: Debug {
    type Error: Display + Debug;
    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), Self::Error>;
    fn subscribe(&mut self, delivery_address: &str) -> Result<(), Self::Error>;
}

/// Manages key bundle storage for MLS group creation/addition while contacts are
/// offline.
///
/// Implement this to provide a contact registry — ach participant publishes their key package
/// on registration; others fetch it to initiate a conversation.
///
/// `register` receives an [`IdentityProvider`] (not just a name) so
/// implementations that need to authenticate the submission — e.g. a network
/// service that verifies the bundle is signed by the correct account — can
/// sign or attest with the caller's key material.
///
/// On testnet a single service (chat-store) provides both the keypackage store
/// and the account service, so [`AccountService`] is a supertrait: any
/// `RegistrationService` also resolves accounts to devices. This co-location is
/// intentional and temporary; the two can be split into separate injected
/// services once λLEZ lands.
pub trait RegistrationService: Debug + AccountService {
    // Disambiguated below: with `AccountService` as a supertrait, a bare
    // `Self::Error` is ambiguous between the two traits' associated types.
    type Error: Display + Debug;
    fn register(
        &mut self,
        identity: &dyn IdentityProvider,
        key_bundle: Vec<u8>,
    ) -> Result<(), <Self as RegistrationService>::Error>;
    fn retrieve(
        &self,
        device_id: &str,
    ) -> Result<Option<Vec<u8>>, <Self as RegistrationService>::Error>;
}

/// Read-only view of a contact registry. Not part of the public API.
/// Satisfied automatically by any `RegistrationService` implementation.
pub trait KeyPackageProvider: Debug {
    type Error: Display + Debug;
    fn retrieve(&self, device_id: &str) -> Result<Option<Vec<u8>>, Self::Error>;
}

impl<T: RegistrationService> KeyPackageProvider for T {
    // Disambiguate: `RegistrationService` now has `AccountService` as a
    // supertrait, so both expose an associated `Error`.
    type Error = <T as RegistrationService>::Error;
    fn retrieve(&self, device_id: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        RegistrationService::retrieve(self, device_id)
    }
}

pub trait WakeupService: Debug {
    fn wakeup_in(&mut self, duration: Duration, convo_id: ConversationId);
}
