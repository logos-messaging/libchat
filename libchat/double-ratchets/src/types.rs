/// Type alias for root keys (32 bytes).
pub type RootKey = [u8; 32];
/// Type alias for chain keys (sending/receiving, 32 bytes).
pub type ChainKey = [u8; 32];
/// Type alias for message keys (32 bytes).
pub type MessageKey = [u8; 32];
/// Type alias for shared secrets/DH outputs (32 bytes).
pub type SharedSecret = [u8; 32];
/// Type alias for a 12-byte AEAD nonce.
pub type Nonce = [u8; 12];
