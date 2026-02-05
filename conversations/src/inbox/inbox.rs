use hex;
use prost::Message;
use prost::bytes::Bytes;
use rand_core::OsRng;
use std::collections::HashMap;
use std::rc::Rc;

use crypto::{PrekeyBundle, SecretKey};
use double_ratchets::storage::RatchetStorage;

use crate::common::{Chat, ChatId, HasChatId, InboundMessageHandler, InboxHandleResult};
use crate::dm::privatev1::PrivateV1Convo;
use crate::errors::ChatError;
use crate::identity::Identity;
use crate::identity::{PublicKey, StaticSecret};
use crate::inbox::handshake::InboxHandshake;
use crate::proto::{self, CopyBytes};
use crate::types::AddressedEncryptedPayload;
use crate::utils::generate_chat_id;

use super::Introduction;

/// Compute the deterministic Delivery_address for an installation
fn delivery_address_for_installation(_: PublicKey) -> String {
    // TODO: Implement Delivery Address
    "delivery_address".into()
}

pub struct Inbox {
    ident: Rc<Identity>,
    local_convo_id: String,
    ephemeral_keys: HashMap<String, StaticSecret>,
}

impl<'a> std::fmt::Debug for Inbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inbox")
            .field("ident", &self.ident)
            .field("convo_id", &self.local_convo_id)
            .field(
                "ephemeral_keys",
                &format!("<{} keys>", self.ephemeral_keys.len()),
            )
            .finish()
    }
}

impl Inbox {
    pub fn new(ident: Rc<Identity>) -> Self {
        let local_convo_id = ident.address();
        Self {
            ident,
            local_convo_id,
            ephemeral_keys: HashMap::<String, StaticSecret>::new(),
        }
    }

    /// Creates a new Inbox with pre-loaded ephemeral keys (for restoring from storage).
    pub fn with_keys(ident: Rc<Identity>, keys: HashMap<String, StaticSecret>) -> Self {
        let local_convo_id = ident.address();
        Self {
            ident,
            local_convo_id,
            ephemeral_keys: keys,
        }
    }

    /// Creates a prekey bundle and returns both the bundle and the ephemeral secret.
    /// The caller is responsible for persisting the secret.
    pub fn create_bundle(&mut self) -> (PrekeyBundle, StaticSecret) {
        let ephemeral = StaticSecret::random();
        let signed_prekey = PublicKey::from(&ephemeral);
        
        // Store in memory
        self.ephemeral_keys
            .insert(hex::encode(signed_prekey.as_bytes()), ephemeral.clone());

        let bundle = PrekeyBundle {
            identity_key: self.ident.public_key(),
            signed_prekey,
            signature: [0u8; 64],
            onetime_prekey: None,
        };

        (bundle, ephemeral)
    }

    /// Removes an ephemeral key after it has been used in a handshake.
    /// Returns the public key hex for the caller to delete from storage.
    pub fn consume_ephemeral_key(&mut self, public_key_hex: &str) -> Option<String> {
        self.ephemeral_keys.remove(public_key_hex).map(|_| public_key_hex.to_string())
    }

    pub fn invite_to_private_convo(
        &self,
        storage: RatchetStorage,
        remote_bundle: &Introduction,
        initial_message: String,
    ) -> Result<(PrivateV1Convo, Vec<AddressedEncryptedPayload>), ChatError> {
        let mut rng = OsRng;

        // TODO: Include signature in introduction bundle. Manaully fill for now
        let pkb = PrekeyBundle {
            identity_key: remote_bundle.installation_key,
            signed_prekey: remote_bundle.ephemeral_key,
            signature: [0u8; 64],
            onetime_prekey: None,
        };

        let (seed_key, ephemeral_pub) =
            InboxHandshake::perform_as_initiator(&self.ident.secret(), &pkb, &mut rng);

        // Generate unique chat ID
        let chat_id = generate_chat_id();
        let mut convo =
            PrivateV1Convo::new_initiator(storage, chat_id, seed_key, remote_bundle.ephemeral_key)?;

        let mut payloads = convo.send_message(initial_message.as_bytes())?;

        // Wrap First payload in Invite
        if let Some(first_message) = payloads.get_mut(0) {
            // Take the the value of .data - it's being replaced at the end of this block
            let frame = Self::wrap_in_invite(std::mem::take(&mut first_message.data));

            // TODO: Encrypt frame
            let ciphertext = frame.encode_to_vec();

            let header = proto::InboxHeaderV1 {
                initiator_static: self.ident.public_key().copy_to_bytes(),
                initiator_ephemeral: ephemeral_pub.copy_to_bytes(),
                responder_static: remote_bundle.installation_key.copy_to_bytes(),
                responder_ephemeral: remote_bundle.ephemeral_key.copy_to_bytes(),
            };

            let handshake = proto::InboxHandshakeV1 {
                header: Some(header),
                payload: Bytes::from_owner(ciphertext),
            };

            // Update the address field with the Inbox delivery_Address
            first_message.delivery_address =
                delivery_address_for_installation(remote_bundle.installation_key);
            // Update the data field with new Payload
            first_message.data = proto::EncryptedPayload {
                encryption: Some(proto::Encryption::InboxHandshake(handshake)),
            };
        }

        Ok((convo, payloads))
    }

    fn wrap_in_invite(payload: proto::EncryptedPayload) -> proto::InboxV1Frame {
        let invite = proto::InvitePrivateV1 {
            discriminator: "default".into(),
            initial_message: Some(payload),
        };

        proto::InboxV1Frame {
            frame_type: Some(
                chat_proto::logoschat::inbox::inbox_v1_frame::FrameType::InvitePrivateV1(invite),
            ),
        }
    }

    fn perform_handshake(
        &self,
        ephemeral_key: &StaticSecret,
        header: proto::InboxHeaderV1,
        bytes: Bytes,
    ) -> Result<(SecretKey, proto::InboxV1Frame), ChatError> {
        // Get PublicKeys from protobuf
        let initator_static = PublicKey::from(
            <[u8; 32]>::try_from(header.initiator_static.as_ref())
                .map_err(|_| ChatError::BadBundleValue("wrong size - initator static".into()))?,
        );

        let initator_ephemeral = PublicKey::from(
            <[u8; 32]>::try_from(header.initiator_ephemeral.as_ref())
                .map_err(|_| ChatError::BadBundleValue("wrong size - initator ephemeral".into()))?,
        );

        let seed_key = InboxHandshake::perform_as_responder(
            self.ident.secret(),
            ephemeral_key,
            None,
            &initator_static,
            &initator_ephemeral,
        );

        // TODO: Decrypt Content
        let frame = proto::InboxV1Frame::decode(bytes)?;
        Ok((seed_key, frame))
    }

    fn extract_payload(
        payload: proto::EncryptedPayload,
    ) -> Result<proto::InboxHandshakeV1, ChatError> {
        let Some(proto::Encryption::InboxHandshake(handshake)) = payload.encryption else {
            let got = format!("{:?}", payload.encryption);

            return Err(ChatError::ProtocolExpectation("inboxhandshake", got));
        };

        Ok(handshake)
    }

    #[allow(dead_code)]
    fn decrypt_frame(
        enc_payload: proto::InboxHandshakeV1,
    ) -> Result<proto::InboxV1Frame, ChatError> {
        let frame_bytes = enc_payload.payload;
        // TODO: decrypt payload
        let frame = proto::InboxV1Frame::decode(frame_bytes)?;
        Ok(frame)
    }

    fn lookup_ephemeral_key(&self, key: &str) -> Result<&StaticSecret, ChatError> {
        self.ephemeral_keys
            .get(key)
            .ok_or_else(|| return ChatError::UnknownEphemeralKey())
    }
}

impl HasChatId for Inbox {
    fn id(&self) -> ChatId<'_> {
        &self.local_convo_id
    }
}

impl InboundMessageHandler for Inbox {
    fn handle_frame(
        &mut self,
        storage: RatchetStorage,
        conversation_hint: &str,
        message: &[u8],
    ) -> Result<InboxHandleResult, ChatError> {
        if message.is_empty() {
            return Err(ChatError::Protocol("empty message".into()));
        }

        let handshake = Self::extract_payload(proto::EncryptedPayload::decode(message)?)?;

        let header = handshake
            .header
            .ok_or(ChatError::UnexpectedPayload("InboxV1Header".into()))?;

        // Extract the remote party's public key
        let remote_public_key: [u8; 32] = header
            .initiator_static
            .as_ref()
            .try_into()
            .map_err(|_| ChatError::InvalidKeyLength)?;

        // Get Ephemeral key used by the initiator
        let key_index = hex::encode(header.responder_ephemeral.as_ref());
        let ephemeral_key = self.lookup_ephemeral_key(&key_index)?;

        // Perform handshake and decrypt frame
        let (seed_key, frame) = self.perform_handshake(ephemeral_key, header, handshake.payload)?;

        match frame.frame_type.ok_or(ChatError::Protocol("missing frame type".into()))? {
            proto::inbox_v1_frame::FrameType::InvitePrivateV1(invite) => {
                // Use the sender's conversation_hint as the shared chat ID
                let chat_id = conversation_hint.to_string();
                let installation_keypair =
                    double_ratchets::InstallationKeyPair::from(ephemeral_key.clone());
                let mut convo = PrivateV1Convo::new_responder(
                    storage,
                    chat_id,
                    seed_key,
                    installation_keypair,
                )?;

                // Decrypt the initial message if present
                let initial_content = if let Some(encrypted_payload) = invite.initial_message {
                    let frame = convo.decrypt(encrypted_payload)?;
                    PrivateV1Convo::extract_content(&frame)
                } else {
                    None
                };

                // Consume the ephemeral key after successful handshake
                self.consume_ephemeral_key(&key_index);

                Ok(InboxHandleResult {
                    convo,
                    remote_public_key,
                    initial_content,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invite_privatev1_roundtrip() {
        let saro_ident = Identity::new();
        let saro_inbox = Inbox::new(saro_ident.into());

        let raya_ident = Identity::new();
        let mut raya_inbox = Inbox::new(raya_ident.into());

        // Create in-memory storage for both parties
        let storage_sender = RatchetStorage::in_memory().unwrap();
        let storage_receiver = RatchetStorage::in_memory().unwrap();

        let (bundle, _secret) = raya_inbox.create_bundle();
        let (saro_convo, payloads) = saro_inbox
            .invite_to_private_convo(storage_sender, &bundle.into(), "hello".into())
            .unwrap();

        // The initiator's conversation ID becomes the shared conversation_hint
        let conversation_hint = saro_convo.id().to_string();

        let payload = payloads
            .get(0)
            .expect("RemoteInbox::invite_to_private_convo did not generate any payloads");

        let mut buf = Vec::new();
        payload.data.encode(&mut buf).unwrap();

        // Test handle_frame with valid payload
        let result = raya_inbox.handle_frame(storage_receiver, &conversation_hint, &buf);

        assert!(
            result.is_ok(),
            "handle_frame should accept valid encrypted payloads: {:?}",
            result.err()
        );

        // Verify we got the decrypted initial message
        let handle_result = result.unwrap();
        assert_eq!(
            handle_result.initial_content,
            Some(b"hello".to_vec()),
            "should decrypt initial message"
        );

        // Verify remote public key was extracted
        assert_eq!(handle_result.remote_public_key.len(), 32);

        // Verify both parties have the same conversation ID
        assert_eq!(
            handle_result.convo.id(),
            saro_convo.id(),
            "both parties should share the same conversation ID"
        );
    }
}
