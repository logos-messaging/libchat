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
    common::{Chat, ChatId, HasChatId},
    errors::{ChatError, EncryptionError},
    proto,
    storage::types::{RatchetStateRecord, SkippedKeyRecord},
    types::AddressedEncryptedPayload,
    utils::timestamp_millis,
};

pub struct PrivateV1Convo {
    chat_id: String,
    dr_state: RatchetState,
}

impl PrivateV1Convo {
    pub fn new_initiator(chat_id: String, seed_key: SecretKey, remote: PublicKey) -> Self {
        // TODO: Danger - Fix double-ratchets types to Accept SecretKey
        // perhaps update the  DH to work with cryptocrate.
        // init_sender doesn't take ownership of the key so a reference can be used.
        let shared_secret: [u8; 32] = seed_key.as_bytes().to_vec().try_into().unwrap();
        Self {
            chat_id,
            dr_state: RatchetState::init_sender(shared_secret, remote),
        }
    }

    pub fn new_responder(chat_id: String, seed_key: SecretKey, dh_self: InstallationKeyPair) -> Self {
        Self {
            chat_id,
            // TODO: Danger - Fix double-ratchets types to Accept SecretKey
            dr_state: RatchetState::init_receiver(seed_key.as_bytes().to_owned(), dh_self),
        }
    }

    /// Restore a conversation from stored ratchet state.
    pub fn from_storage(
        chat_id: String,
        state: RatchetStateRecord,
        skipped_keys: Vec<SkippedKeyRecord>,
    ) -> Self {
        use std::collections::HashMap;

        let dh_self = InstallationKeyPair::from_secret_bytes(state.dh_self_secret);
        let dh_remote = state.dh_remote.map(PublicKey::from);

        let skipped: HashMap<(PublicKey, u32), [u8; 32]> = skipped_keys
            .into_iter()
            .map(|sk| ((PublicKey::from(sk.public_key), sk.msg_num), sk.message_key))
            .collect();

        let dr_state = RatchetState::from_parts(
            state.root_key,
            state.sending_chain,
            state.receiving_chain,
            dh_self,
            dh_remote,
            state.msg_send,
            state.msg_recv,
            state.prev_chain_len,
            skipped,
        );

        Self { chat_id, dr_state }
    }

    /// Get the current ratchet state for storage.
    pub fn to_storage(&self) -> (RatchetStateRecord, Vec<SkippedKeyRecord>) {
        let state = RatchetStateRecord {
            root_key: self.dr_state.root_key,
            sending_chain: self.dr_state.sending_chain,
            receiving_chain: self.dr_state.receiving_chain,
            dh_self_secret: *self.dr_state.dh_self.secret_bytes(),
            dh_remote: self.dr_state.dh_remote.map(|pk| pk.to_bytes()),
            msg_send: self.dr_state.msg_send,
            msg_recv: self.dr_state.msg_recv,
            prev_chain_len: self.dr_state.prev_chain_len,
        };

        let skipped_keys: Vec<SkippedKeyRecord> = self
            .dr_state
            .skipped_keys
            .iter()
            .map(|((pk, msg_num), key)| SkippedKeyRecord {
                public_key: pk.to_bytes(),
                msg_num: *msg_num,
                message_key: *key,
            })
            .collect();

        (state, skipped_keys)
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

        // Turn the bytes into a PublicKey
        let byte_arr: [u8; 32] = dr_header
            .dh
            .to_vec()
            .try_into()
            .map_err(|_| EncryptionError::Decryption("invalid public key length".into()))?;
        let dh_pub = PublicKey::from(byte_arr);

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
}

impl HasChatId for PrivateV1Convo {
    fn id(&self) -> ChatId<'_> {
        &self.chat_id
    }
}

impl Chat for PrivateV1Convo {
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

#[cfg(test)]
mod tests {
    use x25519_dalek::StaticSecret;

    use super::*;

    #[test]
    fn test_encrypt_roundtrip() {
        let saro = StaticSecret::random();
        let raya = StaticSecret::random();

        let pub_raya = PublicKey::from(&raya);

        let seed_key = saro.diffie_hellman(&pub_raya);
        let send_content_bytes = vec![0, 2, 4, 6, 8];
        let mut sr_convo = PrivateV1Convo::new_initiator(
            "test_chat".to_string(),
            SecretKey::from(seed_key.to_bytes()),
            pub_raya,
        );

        let installation_key_pair = InstallationKeyPair::from(raya);
        let mut rs_convo = PrivateV1Convo::new_responder(
            "test_chat".to_string(),
            SecretKey::from(seed_key.to_bytes()),
            installation_key_pair,
        );

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
