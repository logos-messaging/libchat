use chat_proto::logoschat::{
    convos::private_v1::{PrivateV1Frame, private_v1_frame::FrameType},
    encryption::{Doubleratchet, EncryptedPayload, encrypted_payload::Encryption},
};
use crypto::SecretKey;
use double_ratchets::{
    Header, InstallationKeyPair,
    storage::{RatchetSession, RatchetStorage},
};
use prost::{Message, bytes::Bytes};
use std::fmt::Debug;
use x25519_dalek::PublicKey;

use crate::{
    common::{Chat, ChatId, HasChatId},
    errors::ChatError,
    proto,
    types::AddressedEncryptedPayload,
    utils::timestamp_millis,
};

pub struct PrivateV1Convo {
    chat_id: String,
    session: RatchetSession,
}

impl PrivateV1Convo {
    /// Create a new conversation as the initiator (sender of first message).
    ///
    /// The session will be persisted to the provided storage.
    pub fn new_initiator(
        storage: RatchetStorage,
        chat_id: String,
        seed_key: SecretKey,
        remote: PublicKey,
    ) -> Result<Self, ChatError> {
        // TODO: Danger - Fix double-ratchets types to Accept SecretKey
        // perhaps update the DH to work with crypto crate.
        let shared_secret: [u8; 32] = seed_key.as_bytes().to_vec().try_into().unwrap();
        let session = RatchetSession::create_sender_session(storage, &chat_id, shared_secret, remote)?;

        Ok(Self { chat_id, session })
    }

    /// Create a new conversation as the responder (receiver of first message).
    ///
    /// The session will be persisted to the provided storage.
    pub fn new_responder(
        storage: RatchetStorage,
        chat_id: String,
        seed_key: SecretKey,
        dh_self: InstallationKeyPair,
    ) -> Result<Self, ChatError> {
        // TODO: Danger - Fix double-ratchets types to Accept SecretKey
        let shared_secret: [u8; 32] = seed_key.as_bytes().to_owned();
        let session = RatchetSession::create_receiver_session(storage, &chat_id, shared_secret, dh_self)?;

        Ok(Self { chat_id, session })
    }

    /// Open an existing conversation from storage.
    pub fn open(storage: RatchetStorage, chat_id: String) -> Result<Self, ChatError> {
        let session = RatchetSession::open(storage, &chat_id)?;

        Ok(Self { chat_id, session })
    }

    /// Consumes the conversation and returns the underlying storage.
    /// Useful when you need to reuse the storage for another conversation.
    pub fn into_storage(self) -> RatchetStorage {
        self.session.into_storage()
    }

    fn encrypt(&mut self, frame: PrivateV1Frame) -> Result<EncryptedPayload, ChatError> {
        let encoded_bytes = frame.encode_to_vec();
        let (cipher_text, header) = self.session.encrypt_message(&encoded_bytes)?;

        Ok(EncryptedPayload {
            encryption: Some(Encryption::Doubleratchet(Doubleratchet {
                dh: Bytes::from(Vec::from(header.dh_pub.to_bytes())),
                msg_num: header.msg_num,
                prev_chain_len: header.prev_chain_len,
                ciphertext: Bytes::from(cipher_text),
                aux: "".into(),
            })),
        })
    }

    /// Decrypt an incoming encrypted payload.
    pub fn decrypt(&mut self, payload: EncryptedPayload) -> Result<PrivateV1Frame, ChatError> {
        // Validate and extract the encryption header or return errors
        let dr_header = if let Some(enc) = payload.encryption {
            if let proto::Encryption::Doubleratchet(dr) = enc {
                dr
            } else {
                return Err(ChatError::Protocol("incorrect encryption type".into()));
            }
        } else {
            return Err(ChatError::Protocol("missing payload".into()));
        };

        // Turn the bytes into a PublicKey
        let byte_arr: [u8; 32] = dr_header
            .dh
            .to_vec()
            .try_into()
            .map_err(|_| ChatError::InvalidKeyLength)?;
        let dh_pub = PublicKey::from(byte_arr);

        // Build the Header that DR impl expects
        let header = Header {
            dh_pub,
            msg_num: dr_header.msg_num,
            prev_chain_len: dr_header.prev_chain_len,
        };

        // Decrypt into Frame
        let content_bytes = self
            .session
            .decrypt_message(&dr_header.ciphertext, header)?;
        
        PrivateV1Frame::decode(content_bytes.as_slice())
            .map_err(|e| ChatError::Protocol(format!("failed to decode frame: {}", e)))
    }

    /// Extract content bytes from a decrypted frame.
    pub fn extract_content(frame: &PrivateV1Frame) -> Option<Vec<u8>> {
        match &frame.frame_type {
            Some(FrameType::Content(bytes)) => Some(bytes.to_vec()),
            _ => None,
        }
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

        let data = self.encrypt(frame)?;

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
            .field("session", &"******")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use double_ratchets::storage::RatchetStorage;
    use x25519_dalek::StaticSecret;

    use super::*;

    #[test]
    fn test_encrypt_roundtrip() {
        let saro = StaticSecret::random();
        let raya = StaticSecret::random();

        let pub_raya = PublicKey::from(&raya);

        let seed_key = saro.diffie_hellman(&pub_raya);
        let send_content_bytes = vec![0, 2, 4, 6, 8];

        // Create in-memory storage for both parties
        let storage_sender = RatchetStorage::in_memory().unwrap();
        let storage_receiver = RatchetStorage::in_memory().unwrap();

        let mut sr_convo = PrivateV1Convo::new_initiator(
            storage_sender,
            "test_chat_sender".to_string(),
            SecretKey::from(seed_key.to_bytes()),
            pub_raya,
        )
        .unwrap();

        let installation_key_pair = InstallationKeyPair::from(raya);
        let mut rs_convo = PrivateV1Convo::new_responder(
            storage_receiver,
            "test_chat_receiver".to_string(),
            SecretKey::from(seed_key.to_bytes()),
            installation_key_pair,
        )
        .unwrap();

        let send_frame = PrivateV1Frame {
            conversation_id: "_".into(),
            sender: Bytes::new(),
            timestamp: timestamp_millis(),
            frame_type: Some(FrameType::Content(Bytes::from(send_content_bytes.clone()))),
        };
        let payload = sr_convo.encrypt(send_frame.clone()).unwrap();
        let recv_frame = rs_convo.decrypt(payload).unwrap();

        assert!(
            recv_frame == send_frame,
            "{:?}. {:?}",
            recv_frame,
            send_content_bytes
        );
    }
}
