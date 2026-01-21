use chat_proto::logoschat::inbox::InboxV1Frame;
use hex;
use prost::Message;
use prost::bytes::Bytes;
use rand_core::OsRng;
use std::collections::HashMap;
use std::rc::Rc;

use crypto::{PrekeyBundle, SecretKey};

use crate::conversation::{ChatError, ConversationId, Convo, ConvoFactory, Id, PrivateV1Convo};
use crate::crypto::{Blake2b128, CopyBytes, Digest, PublicKey, StaticSecret};
use crate::identity::Identity;
use crate::inbox::handshake::InboxHandshake;
use crate::proto::{self};
use crate::types::ContentData;

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

    fn compute_local_convo_id(addr: &str) -> String {
        let hash = Blake2b128::digest(format!("{}:{}:{}", "logoschat", "inboxV1", addr));
        hex::encode(hash)
    }

    pub fn create_bundle(&mut self) -> PrekeyBundle {
        let ephemeral = StaticSecret::random();

        let signed_prekey = PublicKey::from(&ephemeral);
        self.ephemeral_keys
            .insert(hex::encode(signed_prekey.as_bytes()), ephemeral);

        PrekeyBundle {
            identity_key: self.ident.public_key(),
            signed_prekey: signed_prekey,
            signature: [0u8; 64],
            onetime_prekey: None,
        }
    }

    pub fn invite_to_private_convo(
        &self,
        remote_bundle: &PrekeyBundle,
        initial_message: String,
    ) -> Result<(PrivateV1Convo, Vec<proto::EncryptedPayload>), ChatError> {
        let mut rng = OsRng;

        let (seed_key, ephemeral_pub) =
            InboxHandshake::perform_as_initiator(&self.ident.secret(), remote_bundle, &mut rng);

        let mut convo = PrivateV1Convo::new(seed_key);

        let mut initial_payloads = convo.send_message(initial_message.as_bytes())?;

        // Wrap First payload in Invite
        if let Some(first_message) = initial_payloads.get_mut(0) {
            let old = first_message.clone();
            let frame = Self::wrap_in_invite(old);

            // TODO: Encrypt frame
            let ciphertext = frame.encode_to_vec();

            let header = proto::InboxHeaderV1 {
                initiator_static: self.ident.public_key().copy_to_bytes(),
                initiator_ephemeral: ephemeral_pub.copy_to_bytes(),
                responder_static: remote_bundle.identity_key.copy_to_bytes(),
                responder_ephemeral: remote_bundle.signed_prekey.copy_to_bytes(),
            };

            let handshake = proto::InboxHandshakeV1 {
                header: Some(header),
                payload: Bytes::from_owner(ciphertext),
            };

            *first_message = proto::EncryptedPayload {
                encryption: Some(proto::Encryption::InboxHandshake(handshake)),
            };
        }

        Ok((convo, initial_payloads))
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
        payload: proto::EncryptedPayload,
    ) -> Result<(SecretKey, proto::InboxV1Frame), ChatError> {
        let handshake = Self::extract_payload(payload)?;
        let header = handshake
            .header
            .ok_or(ChatError::UnexpectedPayload("InboxV1Header".into()))?;
        let pubkey_hex = hex::encode(header.responder_ephemeral.as_ref());

        let ephemeral_key = self.lookup_ephemeral_key(&pubkey_hex)?;

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
        let frame = InboxV1Frame::decode(handshake.payload)?;
        Ok((seed_key, frame))
    }

    fn extract_payload(
        payload: proto::EncryptedPayload,
    ) -> Result<proto::InboxHandshakeV1, ChatError> {
        let Some(proto::Encryption::InboxHandshake(handshake)) = payload.encryption else {
            return Err(ChatError::Protocol(
                "Expected inboxhandshake encryption".into(),
            ));
        };

        Ok(handshake)
    }

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

impl Id for Inbox {
    fn id(&self) -> ConversationId {
        &self.local_convo_id
    }
}

impl ConvoFactory for Inbox {
    fn handle_frame(
        &mut self,
        message: &[u8],
    ) -> Result<(Box<dyn Convo>, Vec<ContentData>), ChatError> {
        if message.len() == 0 {
            return Err(ChatError::Protocol("Example error".into()));
        }

        let ep = proto::EncryptedPayload::decode(message)?;
        let (seed_key, frame) = self.perform_handshake(ep)?;

        match frame.frame_type.unwrap() {
            chat_proto::logoschat::inbox::inbox_v1_frame::FrameType::InvitePrivateV1(
                _invite_private_v1,
            ) => {
                let convo = PrivateV1Convo::new(seed_key);
                // TODO: Update PrivateV1 Constructor with DR, initial_message
                Ok((Box::new(convo), vec![]))
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

        let bundle = raya_inbox.create_bundle();
        let (_, payloads) = saro_inbox
            .invite_to_private_convo(&bundle, "hello".into())
            .unwrap();

        let encrypted_payload = payloads
            .get(0)
            .expect("RemoteInbox::invite_to_private_convo did not generate any payloads");

        let mut buf = Vec::new();
        encrypted_payload.encode(&mut buf).unwrap();

        // Test handle_frame with valid payload
        let result = raya_inbox.handle_frame(&buf);

        assert!(
            result.is_ok(),
            "handle_frame should accept valid encrypted payloads"
        );
    }
}
