mod session;
mod sqlite;

pub use session::{RatchetSession, SessionError};
pub use sqlite::{SqliteStorage, StorageConfig};

use crate::{
    hkdf::HkdfInfo,
    state::{RatchetState, SkippedKey},
    types::MessageKey,
};
use thiserror::Error;
use x25519_dalek::PublicKey;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("conversation not found: {0}")]
    ConversationNotFound(String),

    #[error("serialization error")]
    Serialization,

    #[error("deserialization error")]
    Deserialization,
}

/// Stored representation of a skipped message key.

/// Raw state data for storage (without generic parameter).
#[derive(Debug, Clone)]
pub struct RatchetStateRecord {
    pub root_key: [u8; 32],
    pub sending_chain: Option<[u8; 32]>,
    pub receiving_chain: Option<[u8; 32]>,
    pub dh_self_secret: [u8; 32],
    pub dh_remote: Option<[u8; 32]>,
    pub msg_send: u32,
    pub msg_recv: u32,
    pub prev_chain_len: u32,
}

impl<D: HkdfInfo> From<&RatchetState<D>> for RatchetStateRecord {
    fn from(state: &RatchetState<D>) -> Self {
        Self {
            root_key: state.root_key,
            sending_chain: state.sending_chain,
            receiving_chain: state.receiving_chain,
            dh_self_secret: state.dh_self.secret_bytes(),
            dh_remote: state.dh_remote.map(|pk| pk.to_bytes()),
            msg_send: state.msg_send,
            msg_recv: state.msg_recv,
            prev_chain_len: state.prev_chain_len,
        }
    }
}

impl RatchetStateRecord {
    pub fn into_ratchet_state<D: HkdfInfo>(self, skipped_keys: Vec<SkippedKey>) -> RatchetState<D> {
        use crate::keypair::InstallationKeyPair;
        use std::collections::HashMap;
        use std::marker::PhantomData;

        let dh_self = InstallationKeyPair::from_secret_bytes(self.dh_self_secret);
        let dh_remote = self.dh_remote.map(PublicKey::from);

        let skipped: HashMap<(PublicKey, u32), MessageKey> = skipped_keys
            .into_iter()
            .map(|sk| ((PublicKey::from(sk.public_key), sk.msg_num), sk.message_key))
            .collect();

        RatchetState {
            root_key: self.root_key,
            sending_chain: self.sending_chain,
            receiving_chain: self.receiving_chain,
            dh_self,
            dh_remote,
            msg_send: self.msg_send,
            msg_recv: self.msg_recv,
            prev_chain_len: self.prev_chain_len,
            skipped_keys: skipped,
            _domain: PhantomData,
        }
    }
}
