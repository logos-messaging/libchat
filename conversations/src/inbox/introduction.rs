use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chat_proto::logoschat::intro::IntroBundle;
use crypto::{Ed25519Signature, PublicKey};
use prost::Message;
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::StaticSecret;

use crate::errors::ChatError;

const BUNDLE_PREFIX: &str = "logos_chatintro_1_";

fn intro_binding_message(ephemeral: &PublicKey) -> Vec<u8> {
    let mut message = Vec::with_capacity(BUNDLE_PREFIX.len() + 32);
    message.extend_from_slice(BUNDLE_PREFIX.as_bytes());
    message.extend_from_slice(ephemeral.as_bytes());
    message
}

pub(crate) fn sign_intro_binding<R: RngCore + CryptoRng>(
    secret: &StaticSecret,
    ephemeral: &PublicKey,
    rng: R,
) -> Ed25519Signature {
    let message = intro_binding_message(ephemeral);
    crypto::xeddsa_sign(secret, &message, rng)
}

pub(crate) fn verify_intro_binding(
    pubkey: &PublicKey,
    ephemeral: &PublicKey,
    signature: &Ed25519Signature,
) -> Result<(), crypto::SignatureError> {
    let message = intro_binding_message(ephemeral);
    crypto::xeddsa_verify(pubkey, &message, signature)
}

/// Supplies remote participants with the required keys to use Inbox protocol
pub struct Introduction {
    installation_key: PublicKey,
    ephemeral_key: PublicKey,
    signature: Ed25519Signature,
}

impl Introduction {
    /// Create a new `Introduction` by signing the ephemeral key with the installation secret.
    pub(crate) fn new<R: RngCore + CryptoRng>(
        installation_secret: &StaticSecret,
        ephemeral_key: PublicKey,
        rng: R,
    ) -> Self {
        let installation_key = installation_secret.into();
        let signature = sign_intro_binding(installation_secret, &ephemeral_key, rng);
        Self {
            installation_key,
            ephemeral_key,
            signature,
        }
    }

    pub fn installation_key(&self) -> &PublicKey {
        &self.installation_key
    }

    pub fn ephemeral_key(&self) -> &PublicKey {
        &self.ephemeral_key
    }

    pub fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }
}

impl From<Introduction> for Vec<u8> {
    fn from(intro: Introduction) -> Vec<u8> {
        let bundle = IntroBundle {
            installation_pubkey: prost::bytes::Bytes::copy_from_slice(
                intro.installation_key.as_bytes(),
            ),
            ephemeral_pubkey: prost::bytes::Bytes::copy_from_slice(intro.ephemeral_key.as_bytes()),
            signature: prost::bytes::Bytes::copy_from_slice(intro.signature.as_ref()),
        };

        let base64_encoded = URL_SAFE_NO_PAD.encode(bundle.encode_to_vec());

        let mut result = String::with_capacity(BUNDLE_PREFIX.len() + base64_encoded.len());
        result.push_str(BUNDLE_PREFIX);
        result.push_str(&base64_encoded);

        result.into_bytes()
    }
}

impl TryFrom<&[u8]> for Introduction {
    type Error = ChatError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let str_value = std::str::from_utf8(value)
            .map_err(|_| ChatError::BadBundleValue("invalid UTF-8".into()))?;

        let base64_part = str_value.strip_prefix(BUNDLE_PREFIX).ok_or_else(|| {
            ChatError::BadBundleValue("not recognized as an introduction bundle".into())
        })?;

        let proto_bytes = URL_SAFE_NO_PAD
            .decode(base64_part)
            .map_err(|_| ChatError::BadBundleValue("invalid base64".into()))?;

        let bundle = IntroBundle::decode(proto_bytes.as_slice())
            .map_err(|_| ChatError::BadBundleValue("invalid protobuf".into()))?;

        let installation_bytes: [u8; 32] = bundle
            .installation_pubkey
            .as_ref()
            .try_into()
            .map_err(|_| ChatError::InvalidKeyLength)?;

        let ephemeral_bytes: [u8; 32] = bundle
            .ephemeral_pubkey
            .as_ref()
            .try_into()
            .map_err(|_| ChatError::InvalidKeyLength)?;

        let signature_bytes: [u8; 64] = bundle
            .signature
            .as_ref()
            .try_into()
            .map_err(|_| ChatError::BadBundleValue("invalid signature length".into()))?;

        let installation_key = PublicKey::from(installation_bytes);
        let ephemeral_key = PublicKey::from(ephemeral_bytes);
        let signature = Ed25519Signature(signature_bytes);

        verify_intro_binding(&installation_key, &ephemeral_key, &signature)
            .map_err(|_| ChatError::BadBundleValue("invalid signature".into()))?;

        Ok(Introduction {
            installation_key,
            ephemeral_key,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn create_test_introduction() -> Introduction {
        let install_secret = StaticSecret::random_from_rng(OsRng);

        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_pub: PublicKey = (&ephemeral_secret).into();

        Introduction::new(&install_secret, ephemeral_pub, OsRng)
    }

    #[test]
    fn test_serialization_roundtrip() {
        let intro = create_test_introduction();
        let original_install = *intro.installation_key();
        let original_ephemeral = *intro.ephemeral_key();
        let original_signature = *intro.signature();

        let encoded: Vec<u8> = intro.into();
        let decoded = Introduction::try_from(encoded.as_slice()).unwrap();

        assert_eq!(*decoded.installation_key(), original_install);
        assert_eq!(*decoded.ephemeral_key(), original_ephemeral);
        assert_eq!(*decoded.signature(), original_signature);
    }

    #[test]
    fn test_invalid_prefix_rejected() {
        assert!(Introduction::try_from(b"wrong_prefix_AAAA".as_slice()).is_err());
    }

    #[test]
    fn test_invalid_base64_rejected() {
        assert!(Introduction::try_from(b"logos_chatintro_1_!!!invalid!!!".as_slice()).is_err());
    }

    #[test]
    fn test_truncated_payload_rejected() {
        let intro = create_test_introduction();
        let encoded: Vec<u8> = intro.into();
        let encoded_str = String::from_utf8(encoded).unwrap();

        let truncated = format!(
            "logos_chatintro_1_{}",
            &encoded_str[BUNDLE_PREFIX.len()..][..10]
        );

        assert!(Introduction::try_from(truncated.as_bytes()).is_err());
    }
}
