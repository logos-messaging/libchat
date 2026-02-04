use crate::proto::{self, Message};

// FFI Type definitions

// This struct represents Outbound data.
// It wraps an encoded payload with a delivery address, so it can be handled by the delivery service.
pub struct AddressedEnvelope {
    pub delivery_address: String,
    pub data: Vec<u8>,
}

// This struct represents the result of processed inbound data.
// It wraps content payload with a conversation_id
pub struct ContentData {
    pub conversation_id: String,
    pub data: Vec<u8>,
    pub isNewConvo: bool, // This feild indicates that
}

// Internal type Definitions

// Used by Conversations to attach addresses to outbound encrypted payloads
pub(crate) struct AddressedEncryptedPayload {
    pub delivery_address: String,
    pub data: proto::EncryptedPayload,
}

impl AddressedEncryptedPayload {
    // Wrap in an envelope and prepare for transmission
    pub fn to_envelope(self, convo_id: String) -> AddressedEnvelope {
        let envelope = proto::EnvelopeV1 {
            // TODO: conversation_id should be obscured
            conversation_hint: convo_id,
            salt: 0,
            payload: proto::Bytes::copy_from_slice(self.data.encode_to_vec().as_slice()),
        };

        AddressedEnvelope {
            delivery_address: self.delivery_address,
            data: envelope.encode_to_vec(),
        }
    }
}
