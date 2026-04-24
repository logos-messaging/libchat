use std::{fmt::Debug, fmt::Display};

use crate::types::{AccountId, AddressedEnvelope};

/// A Delivery service is responsible for payload transport.
/// This interface allows Conversations to send payloads on the wire as well as
/// register interest in delivery_addresses. Client implementations are responsible
/// for providing the inbound payloads to Context::handle_payload.
pub trait DeliveryService: Debug {
    type Error: Display;
    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), Self::Error>;
    fn subscribe(&mut self, delivery_address: &str) -> Result<(), Self::Error>;
}

/// Manages key bundle storage for MLS group creation/addition while contacts are
/// offline.
///
/// Implement this to provide a contact registry — ach participant publishes their key package
/// on registration; others fetch it to initiate a conversation.
pub trait RegistrationService: Debug {
    type Error: Display;
    fn register(&mut self, identity: &str, key_bundle: Vec<u8>) -> Result<(), Self::Error>;
    fn retrieve(&self, identity: &AccountId) -> Result<Option<Vec<u8>>, Self::Error>;
}

/// Read-only view of a contact registry. Not part of the public API.
/// Satisfied automatically by any `RegistrationService` implementation.
pub trait KeyPackageProvider: Debug {
    type Error: Display;
    fn retrieve(&self, identity: &AccountId) -> Result<Option<Vec<u8>>, Self::Error>;
}

impl<T: RegistrationService> KeyPackageProvider for T {
    type Error = T::Error;
    fn retrieve(&self, identity: &AccountId) -> Result<Option<Vec<u8>>, Self::Error> {
        RegistrationService::retrieve(self, identity)
    }
}
