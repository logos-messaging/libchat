use blake2::{Blake2b512, Digest};
use chat_proto::logoschat::encryption::EncryptedPayload;
use prost::Message;
use prost::bytes::Bytes;
use rand_core::OsRng;
use std::collections::HashMap;
use std::rc::Rc;

use crypto::{PrekeyBundle, SymmetricKey32};

use crate::context::Introduction;
use crate::conversation::{ChatError, ConversationId, Convo, Id, PrivateV1Convo};
use crate::crypto::{CopyBytes, X25519PrivateKey, X25519PublicKey};
use crate::identity::Identity;
use crate::inbox::handshake::InboxHandshake;
use crate::proto;
use crate::types::{AddressedEncryptedPayload, ContentData};

/// Compute the deterministic Delivery_address for an installation
fn delivery_address_for_installation(_: X25519PublicKey) -> String {
    // TODO: Implement Delivery Address
    "delivery_address".into()
}

pub struct Inbox {
    ident: Rc<Identity>,
    local_convo_id: String,
    ephemeral_keys: HashMap<String, X25519PrivateKey>,
}

impl std::fmt::Debug for Inbox {
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
        let local_convo_id = Self::inbox_identifier_for_key(ident.public_key());
        Self {
            ident,
            local_convo_id,
            ephemeral_keys: HashMap::<String, X25519PrivateKey>::new(),
        }
    }

    pub fn create_intro_bundle(&mut self) -> Introduction {
        let ephemeral = X25519PrivateKey::random();

        let ephemeral_key: X25519PublicKey = (&ephemeral).into();
        self.ephemeral_keys
            .insert(hex::encode(ephemeral_key.as_bytes()), ephemeral);

        Introduction::new(self.ident.secret(), ephemeral_key, OsRng)
    }

    pub fn invite_to_private_convo(
        &self,
        remote_bundle: &Introduction,
        initial_message: &[u8],
    ) -> Result<(PrivateV1Convo, Vec<AddressedEncryptedPayload>), ChatError> {
        let mut rng = OsRng;

        let pkb = PrekeyBundle {
            identity_key: *remote_bundle.installation_key(),
            signed_prekey: *remote_bundle.ephemeral_key(),
            signature: *remote_bundle.signature(),
            onetime_prekey: None,
        };

        let (seed_key, ephemeral_pub) =
            InboxHandshake::perform_as_initiator(self.ident.secret(), &pkb, &mut rng);

        let mut convo = PrivateV1Convo::new_initiator(seed_key, *remote_bundle.ephemeral_key());

        let mut payloads = convo.send_message(initial_message)?;

        // Wrap First payload in Invite
        if let Some(first_message) = payloads.get_mut(0) {
            // Take the the value of .data - it's being replaced at the end of this block
            let frame = Self::wrap_in_invite(std::mem::take(&mut first_message.data));

            // TODO: Encrypt frame
            let ciphertext = frame.encode_to_vec();

            let header = proto::InboxHeaderV1 {
                initiator_static: self.ident.public_key().copy_to_bytes(),
                initiator_ephemeral: ephemeral_pub.copy_to_bytes(),
                responder_static: remote_bundle.installation_key().copy_to_bytes(),
                responder_ephemeral: remote_bundle.ephemeral_key().copy_to_bytes(),
            };

            let handshake = proto::InboxHandshakeV1 {
                header: Some(header),
                payload: Bytes::from_owner(ciphertext),
            };

            // Update the address field with the Inbox delivery_Address
            first_message.delivery_address =
                delivery_address_for_installation(*remote_bundle.installation_key());
            // Update the data field with new Payload
            first_message.data = proto::EncryptedPayload {
                encryption: Some(proto::Encryption::InboxHandshake(handshake)),
            };
        }

        Ok((convo, payloads))
    }

    pub fn handle_frame(
        &mut self,
        enc_payload: EncryptedPayload,
    ) -> Result<(Box<dyn Convo>, Option<ContentData>), ChatError> {
        let handshake = Self::extract_payload(enc_payload)?;

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
                let mut convo =
                    PrivateV1Convo::new_responder(seed_key, ephemeral_key.clone().into());

                let Some(enc_payload) = _invite_private_v1.initial_message else {
                    return Err(ChatError::Protocol("missing initial encpayload".into()));
                };

                // Set is_new_convo for content data
                let content = match convo.handle_frame(enc_payload)? {
                    Some(v) => ContentData {
                        is_new_convo: true,
                        ..v
                    },
                    None => return Err(ChatError::Protocol("expected contentData".into())),
                };

                Ok((Box::new(convo), Some(content)))
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
        ephemeral_key: &X25519PrivateKey,
        header: proto::InboxHeaderV1,
        bytes: Bytes,
    ) -> Result<(SymmetricKey32, proto::InboxV1Frame), ChatError> {
        // Get X25519PublicKeys from protobuf
        let initator_static = X25519PublicKey::from(
            <[u8; 32]>::try_from(header.initiator_static.as_ref())
                .map_err(|_| ChatError::BadBundleValue("wrong size - initator static".into()))?,
        );

        let initator_ephemeral = X25519PublicKey::from(
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
        let frame = self.decrypt_frame(bytes)?;
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

    fn decrypt_frame(&self, enc_frame_bytes: Bytes) -> Result<proto::InboxV1Frame, ChatError> {
        // TODO: decrypt payload
        let frame = proto::InboxV1Frame::decode(enc_frame_bytes)?;
        Ok(frame)
    }

    fn lookup_ephemeral_key(&self, key: &str) -> Result<&X25519PrivateKey, ChatError> {
        self.ephemeral_keys
            .get(key)
            .ok_or(ChatError::UnknownEphemeralKey())
    }

    pub fn inbox_identifier_for_key(pubkey: X25519PublicKey) -> String {
        // TODO: Implement ID according to spec
        hex::encode(Blake2b512::digest(pubkey))
    }
}

impl Id for Inbox {
    fn id(&self) -> ConversationId<'_> {
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

        let bundle = raya_inbox.create_intro_bundle();
        let (_, mut payloads) = saro_inbox
            .invite_to_private_convo(&bundle, "hello".as_bytes())
            .unwrap();

        let payload = payloads.remove(0);

        // Test handle_frame with valid payload
        let result = raya_inbox.handle_frame(payload.data);

        assert!(
            result.is_ok(),
            "handle_frame should accept valid encrypted payloads"
        );
    }
}
