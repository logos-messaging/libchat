pub use chat_proto::logoschat::encryption::encrypted_payload::Encryption;
pub use chat_proto::logoschat::encryption::inbox_handshake_v1::InboxHeaderV1;
pub use chat_proto::logoschat::encryption::{EncryptedPayload, InboxHandshakeV1};
pub use chat_proto::logoschat::envelope::EnvelopeV1;
pub use chat_proto::logoschat::inbox::{InboxV1Frame, inbox_v1_frame};
pub use chat_proto::logoschat::invite::InvitePrivateV1;

pub use prost::Message;
pub use prost::bytes::Bytes;
use x25519_dalek::PublicKey;

pub trait CopyBytes {
    fn copy_to_bytes(&self) -> Bytes;
}

impl CopyBytes for PublicKey {
    fn copy_to_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(self.as_bytes())
    }
}
