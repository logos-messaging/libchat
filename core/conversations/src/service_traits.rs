/// Service traits define the functionality which must be externally supplied by
/// platform clients. Platforms can alter the behaviour of the chat core by supplying
/// different implementations.
use std::sync::{Mutex, mpsc};
use std::{fmt::Debug, fmt::Display};

use crate::types::{AccountId, AddressedEnvelope};

pub fn drain_inbound(rx: &Mutex<mpsc::Receiver<Vec<u8>>>) -> Vec<Vec<u8>> {
    let rx = rx.lock().unwrap();
    let mut out = Vec::new();
    while let Ok(bytes) = rx.try_recv() {
        out.push(bytes);
    }
    out
}

/// A Delivery service is responsible for payload transport.
/// This interface allows Conversations to send payloads on the wire, register
/// interest in delivery_addresses, and pull inbound payloads.
pub trait DeliveryService: Debug + Send + Sync {
    type Error: Display + Debug;
    fn publish(&self, envelope: AddressedEnvelope) -> Result<(), Self::Error>;
    fn subscribe(&self, delivery_address: &str) -> Result<(), Self::Error>;

    /// Return every inbound payload that has arrived since the last call.
    /// Non-blocking; returns an empty vec when nothing is available.
    fn pull(&self) -> Vec<Vec<u8>>;
}

/// Manages key bundle storage for MLS group creation/addition while contacts are
/// offline.
///
/// Implement this to provide a contact registry — ach participant publishes their key package
/// on registration; others fetch it to initiate a conversation.
pub trait RegistrationService: Debug {
    type Error: Display + Debug;
    fn register(&mut self, identity: &str, key_bundle: Vec<u8>) -> Result<(), Self::Error>;
    fn retrieve(&self, identity: &AccountId) -> Result<Option<Vec<u8>>, Self::Error>;
}

/// Read-only view of a contact registry. Not part of the public API.
/// Satisfied automatically by any `RegistrationService` implementation.
pub trait KeyPackageProvider: Debug {
    type Error: Display + Debug;
    fn retrieve(&self, identity: &AccountId) -> Result<Option<Vec<u8>>, Self::Error>;
}

impl<T: RegistrationService> KeyPackageProvider for T {
    type Error = T::Error;
    fn retrieve(&self, identity: &AccountId) -> Result<Option<Vec<u8>>, Self::Error> {
        RegistrationService::retrieve(self, identity)
    }
}
