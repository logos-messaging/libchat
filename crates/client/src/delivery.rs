use libchat::AddressedEnvelope;

pub trait DeliveryService {
    type Error: std::fmt::Debug;
    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), Self::Error>;
}
