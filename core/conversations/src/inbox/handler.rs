use blake2::{Blake2b512, Digest};
use chat_proto::logoschat::encryption::EncryptedPayload;
use prost::Message;
use prost::bytes::Bytes;
use rand_core::OsRng;
use storage::EphemeralKeyStore;

use crypto::{PrekeyBundle, SymmetricKey32};

use crate::conversation::{ChatError, Convo, PrivateV1Convo};
use crate::crypto::{CopyBytes, PrivateKey, PublicKey};
use crate::inbox::Introduction;
use crate::inbox::handshake::InboxHandshake;
use crate::outcomes::{ConversationClass, InboxOutcome, NewConversation};
use crate::proto;
use crate::service_context::{ExternalServices, ServiceContext};
use crate::types::AddressedEncryptedPayload;
use crypto::Identity;

/// Transport address shared by all PrivateV1 inbox traffic.
pub const PRIVATE_V1_INBOX_ADDRESS: &str = "delivery_address";

/// Compute the deterministic Delivery_address for an installation
fn delivery_address_for_installation(_: PublicKey) -> String {
    // TODO: Implement Delivery Address
    PRIVATE_V1_INBOX_ADDRESS.into()
}

pub struct Inbox {
    local_convo_id: String,
}

impl std::fmt::Debug for Inbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inbox")
            .field("convo_id", &self.local_convo_id)
            .finish()
    }
}

impl Inbox {
    pub fn new(ident: &Identity) -> Self {
        let local_convo_id = Self::inbox_identifier_for_key(ident.public_key());
        Self { local_convo_id }
    }

    /// Creates an intro bundle and returns the Introduction along with the
    /// generated ephemeral key pair (public_key_hex, private_key) for the caller to persist.
    pub fn create_intro_bundle<S: ExternalServices>(
        &self,
        cx: &mut ServiceContext<S>,
    ) -> Result<Introduction, ChatError> {
        let ephemeral = PrivateKey::random();

        let ephemeral_key: PublicKey = (&ephemeral).into();
        let public_key_hex = hex::encode(ephemeral_key.as_bytes());

        cx.store.save_ephemeral_key(&public_key_hex, &ephemeral)?;

        let intro = Introduction::new(cx.identity.secret(), ephemeral_key, OsRng);
        Ok(intro)
    }

    pub fn invite_to_private_convo<S: ExternalServices>(
        &self,
        cx: &mut ServiceContext<S>,
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
            InboxHandshake::perform_as_initiator(cx.identity.secret(), &pkb, &mut rng);

        let mut convo = PrivateV1Convo::new_initiator(seed_key, *remote_bundle.ephemeral_key());

        let mut payloads = convo.encrypt_content(initial_message, &mut cx.store)?;

        // Wrap First payload in Invite
        if let Some(first_message) = payloads.get_mut(0) {
            // Take the the value of .data - it's being replaced at the end of this block
            let frame = Self::wrap_in_invite(std::mem::take(&mut first_message.data));

            // TODO: Encrypt frame
            let ciphertext = frame.encode_to_vec();

            let header = proto::InboxHeaderV1 {
                initiator_static: cx.identity.public_key().copy_to_bytes(),
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

    /// Handles an incoming inbox frame. The caller must provide the ephemeral
    /// private key hex looked up from storage. Persists the created
    /// conversation and consumes the ephemeral key. Returns the
    /// [`InboxOutcome`] describing what was observed — for a successful
    /// invite, a `new_conversation` and the initial `ConvoOutcome` carrying
    /// the first message.
    pub fn handle_frame<S: ExternalServices>(
        &self,
        cx: &mut ServiceContext<S>,
        enc_payload: EncryptedPayload,
        public_key_hex: &str,
    ) -> Result<InboxOutcome, ChatError> {
        let ephemeral_key = cx
            .store
            .load_ephemeral_key(public_key_hex)?
            .ok_or(ChatError::UnknownEphemeralKey())?;

        let handshake = Self::extract_payload(enc_payload)?;

        let header = handshake
            .header
            .ok_or(ChatError::UnexpectedPayload("InboxV1Header".into()))?;

        // Perform handshake and decrypt frame
        let (seed_key, frame) =
            self.perform_handshake(&cx.identity, &ephemeral_key, header, handshake.payload)?;

        let result = match frame.frame_type.unwrap() {
            proto::inbox_v1_frame::FrameType::InvitePrivateV1(_invite_private_v1) => {
                let mut convo = PrivateV1Convo::new_responder(seed_key, &ephemeral_key);

                let Some(enc_payload) = _invite_private_v1.initial_message else {
                    return Err(ChatError::Protocol("missing initial encpayload".into()));
                };

                let initial = convo.handle_frame(cx, enc_payload)?;
                if initial.content.is_none() {
                    return Err(ChatError::Protocol(
                        "expected initial message in invite".into(),
                    ));
                }

                let new_conversation = NewConversation {
                    convo_id: initial.convo_id.clone(),
                    class: ConversationClass::Private,
                };
                convo.persist(&mut cx.store)?;

                InboxOutcome {
                    new_conversation,
                    initial: Some(initial),
                }
            }
        };

        cx.store.remove_ephemeral_key(public_key_hex)?;

        Ok(result)
    }

    /// Extracts the ephemeral key hex from an incoming encrypted payload
    /// so the caller can look it up from storage before calling handle_frame.
    pub fn extract_ephemeral_key_hex(enc_payload: &EncryptedPayload) -> Result<String, ChatError> {
        let Some(proto::Encryption::InboxHandshake(ref handshake)) = enc_payload.encryption else {
            let got = format!("{:?}", enc_payload.encryption);
            return Err(ChatError::ProtocolExpectation("inboxhandshake", got));
        };

        let header = handshake
            .header
            .as_ref()
            .ok_or(ChatError::UnexpectedPayload("InboxV1Header".into()))?;

        Ok(hex::encode(header.responder_ephemeral.as_ref()))
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
        ident: &Identity,
        ephemeral_key: &PrivateKey,
        header: proto::InboxHeaderV1,
        bytes: Bytes,
    ) -> Result<(SymmetricKey32, proto::InboxV1Frame), ChatError> {
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
            ident.secret(),
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

    pub fn inbox_identifier_for_key(pubkey: PublicKey) -> String {
        // TODO: Implement ID according to spec
        hex::encode(Blake2b512::digest(pubkey))
    }

    pub fn id(&self) -> &str {
        &self.local_convo_id
    }

    /// Transport address this inbox receives PrivateV1 traffic on.
    pub fn delivery_address(&self) -> &str {
        PRIVATE_V1_INBOX_ADDRESS
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use chat_sqlite::{ChatStorage, StorageConfig};
    use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
    use logos_traits::{IdentId, IdentityProvider};

    struct Identity {
        name: IdentId,
        key: Ed25519SigningKey,
        verify: Ed25519VerifyingKey,
    }

    impl Identity {
        pub fn new(name: impl Into<String>) -> Self {
            let key = Ed25519SigningKey::generate();
            let verify = key.verifying_key();
            Identity {
                name: IdentId::new(name.into()),
                key,
                verify,
            }
        }
    }

    impl IdentityProvider for Identity {
        fn id(&self) -> logos_traits::IdentIdRef<'_> {
            &self.name
        }

        fn display_name(&self) -> String {
            self.name.to_string()
        }

        fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
            self.key.sign(payload)
        }

        fn public_key(&self) -> &crypto::Ed25519VerifyingKey {
            &self.verify
        }
    }

    #[test]
    fn test_invite_privatev1_roundtrip() {
        let saro_storage = ChatStorage::new(StorageConfig::InMemory).unwrap();
        let raya_storage = ChatStorage::new(StorageConfig::InMemory).unwrap();

        let saro_account = Identity::new("saro");
        let raya_account = Identity::new("raya");

        let mut saro_cx = ServiceContext::for_test(saro_account, saro_storage).unwrap();
        let saro_inbox = Inbox::new(&saro_cx.identity);

        let mut raya_cx = ServiceContext::for_test(raya_account, raya_storage).unwrap();
        let raya_inbox = Inbox::new(&raya_cx.identity);

        let bundle = raya_inbox.create_intro_bundle(&mut raya_cx).unwrap();

        let (_, mut payloads) = saro_inbox
            .invite_to_private_convo(&mut saro_cx, &bundle, "hello".as_bytes())
            .unwrap();

        let payload = payloads.remove(0);
        let key_hex = Inbox::extract_ephemeral_key_hex(&payload.data).unwrap();

        let result = raya_inbox.handle_frame(&mut raya_cx, payload.data, &key_hex);

        assert!(
            result.is_ok(),
            "handle_frame should accept valid encrypted payloads"
        );
    }
}
