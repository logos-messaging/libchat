use blake2::{
    Blake2b, Blake2bMac, Digest,
    digest::{FixedOutput, consts::U18},
};
use chat_proto::logoschat::{
    convos::private_v1::{PrivateV1Frame, private_v1_frame::FrameType},
    encryption::{Doubleratchet, EncryptedPayload, encrypted_payload::Encryption},
};
use crypto::SymmetricKey32;
use crypto::X25519PublicKey;
use double_ratchets::{Header, InstallationKeyPair, RatchetState};
use prost::{Message, bytes::Bytes};
use std::fmt::Debug;

use crate::{
    conversation::{ChatError, ConversationId, Convo, Id},
    errors::EncryptionError,
    proto,
    types::{AddressedEncryptedPayload, ContentData},
    utils::timestamp_millis,
};

// Represents the potential participant roles in this Conversation
enum Role {
    Initiator,
    Responder,
}

impl Role {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Initiator => "I",
            Self::Responder => "R",
        }
    }
}

struct BaseConvoId([u8; 18]);

impl BaseConvoId {
    fn new(key: &SymmetricKey32) -> Self {
        let base = Blake2bMac::<U18>::new_with_salt_and_personal(key.as_bytes(), b"", b"L-PV1-CID")
            .expect("fixed inputs should never fail");
        Self(base.finalize_fixed().into())
    }

    fn id_for_participant(&self, role: Role) -> String {
        let hash = Blake2b::<U18>::new()
            .chain_update(self.0)
            .chain_update(role.as_str())
            .finalize();
        hex::encode(hash)
    }
}

pub struct PrivateV1Convo {
    local_convo_id: String,
    remote_convo_id: String,
    dr_state: RatchetState,
}

impl PrivateV1Convo {
    pub fn new_initiator(seed_key: SymmetricKey32, remote: X25519PublicKey) -> Self {
        let base_convo_id = BaseConvoId::new(&seed_key);
        let local_convo_id = base_convo_id.id_for_participant(Role::Initiator);
        let remote_convo_id = base_convo_id.id_for_participant(Role::Responder);

        // TODO: Danger - Fix double-ratchets types to Accept SymmetricKey32
        // perhaps update the  DH to work with cryptocrate.
        // init_sender doesn't take ownership of the key so a reference can be used.
        let shared_secret: [u8; 32] = seed_key.DANGER_to_bytes();
        let dr_state = RatchetState::init_sender(shared_secret, remote);

        Self {
            local_convo_id,
            remote_convo_id,
            dr_state,
        }
    }

    pub fn new_responder(
        seed_key: SymmetricKey32,
        dh_self: InstallationKeyPair, // TODO: (P3) Rename; This accepts a Ephemeral key in most cases
    ) -> Self {
        let base_convo_id = BaseConvoId::new(&seed_key);
        let local_convo_id = base_convo_id.id_for_participant(Role::Responder);
        let remote_convo_id = base_convo_id.id_for_participant(Role::Initiator);

        // TODO: Danger - Fix double-ratchets types to Accept SymmetricKey32
        let dr_state = RatchetState::init_receiver(seed_key.DANGER_to_bytes(), dh_self);

        Self {
            local_convo_id,
            remote_convo_id,
            dr_state,
        }
    }

    fn encrypt(&mut self, frame: PrivateV1Frame) -> EncryptedPayload {
        let encoded_bytes = frame.encode_to_vec();
        let (cipher_text, header) = self.dr_state.encrypt_message(&encoded_bytes);

        EncryptedPayload {
            encryption: Some(Encryption::Doubleratchet(Doubleratchet {
                dh: Bytes::from(Vec::from(header.dh_pub.to_bytes())),
                msg_num: header.msg_num,
                prev_chain_len: header.prev_chain_len,
                ciphertext: Bytes::from(cipher_text),
                aux: "".into(),
            })),
        }
    }

    fn decrypt(&mut self, payload: EncryptedPayload) -> Result<PrivateV1Frame, EncryptionError> {
        // Validate and extract the encryption header or return errors
        let dr_header = if let Some(enc) = payload.encryption {
            if let proto::Encryption::Doubleratchet(dr) = enc {
                dr
            } else {
                return Err(EncryptionError::Decryption(
                    "incorrect encryption type".into(),
                ));
            }
        } else {
            return Err(EncryptionError::Decryption("missing payload".into()));
        };

        // Turn the bytes into a X25519PublicKey
        let byte_arr: [u8; 32] = dr_header
            .dh
            .to_vec()
            .try_into()
            .map_err(|_| EncryptionError::Decryption("invalid public key length".into()))?;
        let dh_pub = X25519PublicKey::from(byte_arr);

        // Build the Header that DR impl expects
        let header = Header {
            dh_pub,
            msg_num: dr_header.msg_num,
            prev_chain_len: dr_header.prev_chain_len,
        };

        // Decrypt into Frame
        let content_bytes = self
            .dr_state
            .decrypt_message(&dr_header.ciphertext, header)
            .map_err(|e| EncryptionError::Decryption(e.to_string()))?;
        Ok(PrivateV1Frame::decode(content_bytes.as_slice()).unwrap())
    }

    // Handler for application content
    fn handle_content(&self, data: Vec<u8>) -> Option<ContentData> {
        Some(ContentData {
            conversation_id: self.id().into(),
            data,
            is_new_convo: false,
        })
    }
}

impl Id for PrivateV1Convo {
    fn id(&self) -> ConversationId<'_> {
        &self.local_convo_id
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

    fn handle_frame(
        &mut self,
        encoded_payload: EncryptedPayload,
    ) -> Result<Option<ContentData>, ChatError> {
        // Extract expected frame
        let frame = self
            .decrypt(encoded_payload)
            .map_err(|_| ChatError::Protocol("decryption".into()))?;

        let Some(frame_type) = frame.frame_type else {
            return Err(ChatError::ProtocolExpectation("None", "Some".into()));
        };

        // Handle FrameTypes
        let output = match frame_type {
            FrameType::Content(bytes) => self.handle_content(bytes.into()),
            FrameType::Placeholder(_) => None,
        };

        Ok(output)
    }

    fn remote_id(&self) -> String {
        self.remote_convo_id.clone()
    }
}

impl Debug for PrivateV1Convo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateV1Convo")
            .field("dr_state", &"******")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use x25519_dalek::StaticSecret;

    use super::*;

    #[test]
    fn test_encrypt_roundtrip() {
        let saro = StaticSecret::random();
        let raya = StaticSecret::random();

        let pub_raya = X25519PublicKey::from(&raya);

        let seed_key = saro.diffie_hellman(&pub_raya);
        let send_content_bytes = vec![0, 2, 4, 6, 8];
        let mut sr_convo = PrivateV1Convo::new_initiator(SymmetricKey32::from(&seed_key), pub_raya);

        let installation_key_pair = InstallationKeyPair::from(raya);
        let mut rs_convo =
            PrivateV1Convo::new_responder(SymmetricKey32::from(&seed_key), installation_key_pair);

        let send_frame = PrivateV1Frame {
            conversation_id: "_".into(),
            sender: Bytes::new(),
            timestamp: timestamp_millis(),
            frame_type: Some(FrameType::Content(Bytes::from(send_content_bytes.clone()))),
        };
        let payload = sr_convo.encrypt(send_frame.clone());
        let recv_frame = rs_convo.decrypt(payload).unwrap();

        assert!(
            recv_frame == send_frame,
            "{:?}. {:?}",
            recv_frame,
            send_content_bytes
        );
    }
}
