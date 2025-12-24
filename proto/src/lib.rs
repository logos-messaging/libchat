mod generated;

use generated::{InboxV1Frame, InvitePrivateV1};
use prost::{DecodeError, Message};

#[cfg(test)]

mod tests {

    use prost::Message;

    use crate::generated::{Doubleratchet, EncryptedPayload};

    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_construct() {
        // Create message
        let msg = InboxV1Frame {
            recipient: "recipient".into(),
            frame_type: Some(generated::inbox_v1_frame::FrameType::InvitePrivateV1(
                InvitePrivateV1 {
                    initiator: vec![0, 1, 2, 3],
                    initiator_ephemeral: vec![0, 1, 2, 3],
                    participant: vec![0, 1, 2, 3],
                    participant_ephemeral_id: 2,
                    discriminator: "".into(),
                    initial_message: Some(EncryptedPayload {
                        encryption: Some(generated::encrypted_payload::Encryption::Doubleratchet(
                            Doubleratchet {
                                dh: vec![10, 11, 12, 13],
                                msg_num: 1,
                                prev_chain_len: 0,
                                ciphertext: vec![9, 8, 7, 6, 5, 4, 3, 2, 1],
                                aux: "".to_string(),
                            },
                        )),
                    }),
                },
            )),
        };
    }
}
