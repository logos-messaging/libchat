// This struct represents Outbound data.
// It wraps an encoded payload with a delivery address, so it can be handled by the delivery service.
pub struct PayloadData {
    pub delivery_address: String,
    pub data: Vec<u8>,
}

// This struct represents the result of processed inbound data.
// It wraps content payload with a conversation_id
pub struct ContentData {
    pub conversation_id: String,
    pub data: Vec<u8>,
}
