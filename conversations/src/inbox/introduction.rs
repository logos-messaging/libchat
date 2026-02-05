use crypto::PrekeyBundle;
use x25519_dalek::PublicKey;

use crate::errors::ChatError;

/// Supplies remote participants with the required keys to use Inbox protocol
#[derive(Clone)]
pub struct Introduction {
    pub installation_key: PublicKey,
    pub ephemeral_key: PublicKey,
}

impl From<PrekeyBundle> for Introduction {
    fn from(value: PrekeyBundle) -> Self {
        Introduction {
            installation_key: value.identity_key,
            ephemeral_key: value.signed_prekey,
        }
    }
}

impl Into<Vec<u8>> for Introduction {
    fn into(self) -> Vec<u8> {
        // TODO: avoid copies, via writing directly to slice
        let link = format!(
            "Bundle:{}:{}",
            hex::encode(self.installation_key.as_bytes()),
            hex::encode(self.ephemeral_key.as_bytes()),
        );

        link.into_bytes()
    }
}

impl TryFrom<&[u8]> for Introduction {
    type Error = ChatError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let str_value = String::from_utf8_lossy(value);
        let parts: Vec<&str> = str_value.splitn(3, ':').collect();

        if parts.len() < 3 || parts[0] != "Bundle" {
            return Err(ChatError::BadBundleValue(
                "not recognized as an introduction bundle".into(),
            ));
        }

        let installation_bytes: [u8; 32] = hex::decode(parts[1])
            .map_err(|_| ChatError::BadParsing("installation_key"))?
            .try_into()
            .map_err(|_| ChatError::InvalidKeyLength)?;
        let installation_key = PublicKey::from(installation_bytes);

        let ephemeral_bytes: [u8; 32] = hex::decode(parts[2])
            .map_err(|_| ChatError::BadParsing("ephemeral_key"))?
            .try_into()
            .map_err(|_| ChatError::InvalidKeyLength)?;
        let ephemeral_key = PublicKey::from(ephemeral_bytes);

        Ok(Introduction {
            installation_key,
            ephemeral_key,
        })
    }
}
