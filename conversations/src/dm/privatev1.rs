use chat_proto::logoschat::{
    convos::private_v1::{PrivateV1Frame, private_v1_frame::FrameType},
    encryption::{Doubleratchet, EncryptedPayload, encrypted_payload::Encryption},
};
use crypto::SecretKey;
use prost::{Message, bytes::Bytes};

use crate::{
    dm::common::{HasConversationId, OutboundSession, SessionId},
    errors::ChatError,
    types::AddressedEncryptedPayload,
    utils::timestamp_millis,
};

#[derive(Debug)]
pub struct PrivateV1Convo {}

impl PrivateV1Convo {
    pub fn new(_seed_key: SecretKey) -> Self {
        Self {}
    }

    fn encrypt(&self, frame: PrivateV1Frame) -> EncryptedPayload {
        // TODO: Integrate DR

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
}

impl HasConversationId for PrivateV1Convo {
    fn id(&self) -> SessionId<'_> {
        // TODO: implementation
        "private_v1_convo_id"
    }
}

impl OutboundSession for PrivateV1Convo {
    fn send_message(
        &mut self,
        content: &[u8],
    ) -> Result<Vec<AddressedEncryptedPayload>, ChatError> {
        let frame = PrivateV1Frame {
            conversation_id: self.id().into(),
            sender: "delete".into(),
            timestamp: timestamp_millis(),
            frame_type: Some(FrameType::Content(content.to_vec().into())),
        };

        let data = self.encrypt(frame);

        Ok(vec![AddressedEncryptedPayload {
            delivery_address: "delivery_address".into(),
            data,
        }])
    }

    fn remote_id(&self) -> String {
        //TODO: Implement as per spec
        self.id().into()
    }
}
