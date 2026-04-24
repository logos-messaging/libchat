use std::{cell::RefCell, fmt::Debug, fmt::Display, rc::Rc};

use crate::types::AddressedEnvelope;

pub struct Service<T> {
    inner: Rc<RefCell<T>>,
}

impl<T> Service<T> {
    pub fn new(t: T) -> Self {
        Self {
            inner: Rc::new(RefCell::new(t)),
        }
    }

    fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        let inner = self.inner.borrow();
        f(&inner)
    }
}

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
