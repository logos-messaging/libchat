/// Service traits define the functionality which must be externally supplied by
/// platform clients. Platforms can alter the behaviour of the chat core by supplying
/// different implementations.
use std::{fmt::Debug, fmt::Display};

use crypto::{Ed25519Signature, Ed25519VerifyingKey};

use crate::{
    ConversationId,
    types::{AccountId, AddressedEnvelope},
};

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

/// Represents an external Identity
/// Implement this to provide an Authentication model for users/installations
pub trait IdentityProvider: Debug {
    fn account_id(&self) -> &AccountId;
    fn friendly_name(&self) -> String;
    fn sign(&self, payload: &[u8]) -> Ed25519Signature;
    fn public_key(&self) -> &Ed25519VerifyingKey;
}

impl<T: IdentityProvider> IdentityProvider for &T {
    fn account_id(&self) -> &AccountId {
        (**self).account_id()
    }
    fn friendly_name(&self) -> String {
        (**self).friendly_name()
    }
    fn sign(&self, payload: &[u8]) -> Ed25519Signature {
        (**self).sign(payload)
    }
    fn public_key(&self) -> &Ed25519VerifyingKey {
        (**self).public_key()
    }
}

pub trait WakeupService: Debug {
    fn wakeup_in(&mut self, secs: u32, convo_id: ConversationId);
}
