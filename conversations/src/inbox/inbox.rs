use hex;
use prost::Message;
use prost::bytes::Bytes;
use rand_core::OsRng;
use std::collections::HashMap;
use std::rc::Rc;

use crypto::{PrekeyBundle, SecretKey};

use crate::context::Introduction;
use crate::conversation::{ChatError, ConversationId, Convo, Id, PrivateV1Convo};
use crate::crypto::{CopyBytes, PublicKey, StaticSecret};
use crate::identity::Identity;
use crate::inbox::handshake::InboxHandshake;
use crate::proto;
use crate::types::{AddressedEncryptedPayload, ContentData};

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

        let mut convo = PrivateV1Convo::new_initiator(seed_key, remote_bundle.ephemeral_key);

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

    fn handle_frame(
        &mut self,
        message: &[u8],
    ) -> Result<(Box<dyn Convo>, Vec<ContentData>), ChatError> {
        if message.len() == 0 {
            return Err(ChatError::Protocol("Example error".into()));
        }

        let handshake = Self::extract_payload(proto::EncryptedPayload::decode(message)?)?;

        let header = handshake
            .header
            .ok_or(ChatError::UnexpectedPayload("InboxV1Header".into()))?;

        // Get Ephemeral key used by the initator
        let key_index = hex::encode(header.responder_ephemeral.as_ref());
        let ephemeral_key = self.lookup_ephemeral_key(&key_index)?;

        // Perform handshake and decrypt frame
        let (seed_key, frame) = self.perform_handshake(ephemeral_key, header, handshake.payload)?;

        match frame.frame_type.unwrap() {
            proto::inbox_v1_frame::FrameType::InvitePrivateV1(_invite_private_v1) => {
                let convo = PrivateV1Convo::new_responder(seed_key, ephemeral_key.clone().into());

                // TODO: Update PrivateV1 Constructor with DR, initial_message
                Ok((Box::new(convo), vec![]))
            }
        }
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
            .invite_to_private_convo(&bundle.into(), "hello".into())
            .unwrap();

        let payload = payloads
            .get(0)
            .expect("RemoteInbox::invite_to_private_convo did not generate any payloads");

        let mut buf = Vec::new();
        payload.data.encode(&mut buf).unwrap();

        // Test handle_frame with valid payload
        let result = raya_inbox.handle_frame(&buf);

        assert!(
            result.is_ok(),
            "handle_frame should accept valid encrypted payloads"
        );
    }
}
