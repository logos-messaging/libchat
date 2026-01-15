use crate::{
    conversation::{ChatError, ConversationId, Convo, Id},
    utils::timestamp_millis,
};
use chat_proto::logoschat::{
    convos::private_v1::{PrivateV1Frame, private_v1_frame::FrameType},
    encryption::{Doubleratchet, EncryptedPayload, encrypted_payload::Encryption},
};
use prost::{Message, bytes::Bytes};

#[derive(Debug)]
pub struct PrivateV1Convo {}

impl PrivateV1Convo {
    pub fn new(_seed_key: [u8; 32]) -> Self {
        Self {}
    }

    fn encrypt(&self, frame: PrivateV1Frame) -> EncryptedPayload {
        EncryptedPayload {
            encryption: Some(Encryption::Doubleratchet(Doubleratchet {
                dh: Bytes::from(vec![]),
                msg_num: 0,
                prev_chain_len: 1,
                ciphertext: Bytes::from(frame.encode_to_vec()),
                aux: "".into(),
            })),
        }
    }

    fn remote_delivery_address(&self) -> String {
        todo!()
    }
}

impl Id for PrivateV1Convo {
    fn id(&self) -> ConversationId {
        // TODO: implementation
        "private_v1_convo_id"
    }
}

impl Convo for PrivateV1Convo {
    fn send_message(&mut self, content: &[u8]) -> Result<Vec<EncryptedPayload>, ChatError> {
        let frame = PrivateV1Frame {
            conversation_id: self.id().into(),
            sender: "delete".into(),
            timestamp: timestamp_millis(),
            frame_type: Some(FrameType::Content(content.to_vec().into())),
        };

        let ef = self.encrypt(frame);

        Ok(vec![ef])
    }

    fn send_frame(&mut self, _message: &[u8]) -> Result<(), ChatError> {
        todo!("Needs DoubleRatchet")
    }

    fn handle_frame(&mut self, _message: &[u8]) -> Result<(), ChatError> {
        todo!()
    }
}
