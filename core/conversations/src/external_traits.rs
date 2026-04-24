use std::{fmt::Debug, fmt::Display};

use crate::types::AddressedEnvelope;

pub trait DeliveryService {
    type Error: Display;
    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), Self::Error>;
    fn subscribe(&mut self, delivery_address: String) -> Result<(), Self::Error>;
}

pub trait RegistrationService: Debug {
    type Error: Display;
    fn register(&mut self, identity: String, key_bundle: Vec<u8>) -> Result<(), Self::Error>;
    fn retreive(&self, identity: &str) -> Result<Option<Vec<u8>>, Self::Error>;
}
