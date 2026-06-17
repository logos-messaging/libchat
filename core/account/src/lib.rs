mod credential;

pub use credential::{
    CREDENTIAL_DOMAIN, CREDENTIAL_VERSION, CredentialError, MessageSender, encode_credential,
    endorse_local_identity, resolve_sender,
};

#[cfg(feature = "dev")]
mod account;

#[cfg(feature = "dev")]
pub use account::TestLogosAccount;
