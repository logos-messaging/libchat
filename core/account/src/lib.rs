mod credential;

pub use credential::{
    CREDENTIAL_DOMAIN, CREDENTIAL_VERSION, CredentialError, MessageSender, SenderCredential,
    decode_credential, encode_credential,
};

#[cfg(feature = "dev")]
mod account;

#[cfg(feature = "dev")]
pub use account::TestLogosAccount;
