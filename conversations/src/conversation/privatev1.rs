use chat_proto::logoschat::{
    convos::private_v1::{PrivateV1Frame, private_v1_frame::FrameType},
    encryption::{Doubleratchet, EncryptedPayload, encrypted_payload::Encryption},
};
use crypto::SecretKey;
use double_ratchets::{Header, InstallationKeyPair, RatchetState};
use prost::{Message, bytes::Bytes};
use std::fmt::Debug;
use x25519_dalek::PublicKey;

use crate::{
    conversation::{ChatError, ConversationId, Convo, Id},
    types::AddressedEncryptedPayload,
    utils::timestamp_millis,
};

pub struct PrivateV1Convo {
    dr_state: RatchetState,
}

impl PrivateV1Convo {
    pub fn new_initiator(seed_key: SecretKey, remote: PublicKey) -> Self {
        // TODO: Danger - Fix double-ratchets types to Accept SecretKey
        // perhaps update the  DH to work with cryptocrate.
        // init_sender doesn't take ownership of the key so a reference can be used.
        let shared_secret: [u8; 32] = seed_key.as_bytes().to_vec().try_into().unwrap();
        Self {
            dr_state: RatchetState::init_sender(shared_secret, remote),
        }
    }

    pub fn new_responder(seed_key: SecretKey, dh_self: InstallationKeyPair) -> Self {
        Self {
            // TODO: Danger - Fix double-ratchets types to Accept SecretKey
            dr_state: RatchetState::init_receiver(seed_key.as_bytes().to_owned(), dh_self),
        }
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

impl Id for PrivateV1Convo {
    fn id(&self) -> ConversationId {
        // TODO: implementation
        "private_v1_convo_id"
    }
}

impl Convo for PrivateV1Convo {
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

impl Debug for PrivateV1Convo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateV1Convo")
            .field("dr_state", &"******")
            .finish()
    }
}
