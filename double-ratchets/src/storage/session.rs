//! Session wrapper for automatic state persistence.

use std::{collections::HashMap, marker::PhantomData};

use x25519_dalek::PublicKey;

use crate::{
    InstallationKeyPair,
    hkdf::HkdfInfo,
    state::{Header, RatchetState},
    types::SharedSecret,
};

use super::{
    SessionError,
    store::{RatchetStateData, RatchetStore, SkippedKeyId, SkippedMessageKey, StoreError},
};

/// Session wrapper with automatic persistence.
pub struct RatchetSession<S: RatchetStore, D: HkdfInfo + Clone> {
    store: S,
    conversation_id: String,
    state: RatchetState<D>,
}

impl<S: RatchetStore, D: HkdfInfo + Clone> RatchetSession<S, D> {
    /// Opens an existing session from storage.
    pub fn open(store: S, conversation_id: impl Into<String>) -> Result<Self, SessionError> {
        let conversation_id = conversation_id.into();
        let data = store
            .load_state(&conversation_id)
            .map_err(|e| map_store_error(e, &conversation_id))?;
        let skipped_keys = store
            .get_all_skipped_keys(&conversation_id)
            .map_err(|e| map_store_error(e, &conversation_id))?;
        let state = state_from_data(data, skipped_keys);

        Ok(Self {
            store,
            conversation_id,
            state,
        })
    }

    /// Creates a new session with the given state.
    pub fn create(
        mut store: S,
        conversation_id: impl Into<String>,
        state: RatchetState<D>,
    ) -> Result<Self, SessionError> {
        let conversation_id = conversation_id.into();
        let data = state_to_data(&state);
        store
            .save_state(&conversation_id, &data)
            .map_err(|e| map_store_error(e, &conversation_id))?;

        for key in get_skipped_keys(&state) {
            store
                .add_skipped_key(&conversation_id, key)
                .map_err(|e| map_store_error(e, &conversation_id))?;
        }

        Ok(Self {
            store,
            conversation_id,
            state,
        })
    }

    /// Creates sender session.
    pub fn create_sender_session(
        store: S,
        conversation_id: &str,
        shared_secret: SharedSecret,
        remote_pub: PublicKey,
    ) -> Result<Self, SessionError> {
        let temp_store = store;
        if temp_store
            .exists(conversation_id)
            .map_err(|e| map_store_error(e, conversation_id))?
        {
            return Err(SessionError::ConvAlreadyExists(conversation_id.to_string()));
        }
        let state = RatchetState::<D>::init_sender(shared_secret, remote_pub);
        Self::create(temp_store, conversation_id, state)
    }

    /// Creates receiver session.
    pub fn create_receiver_session(
        store: S,
        conversation_id: &str,
        shared_secret: SharedSecret,
        dh_self: InstallationKeyPair,
    ) -> Result<Self, SessionError> {
        let temp_store = store;
        if temp_store
            .exists(conversation_id)
            .map_err(|e| map_store_error(e, conversation_id))?
        {
            return Err(SessionError::ConvAlreadyExists(conversation_id.to_string()));
        }
        let state = RatchetState::<D>::init_receiver(shared_secret, dh_self);
        Self::create(temp_store, conversation_id, state)
    }

    /// Encrypts a message.
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<(Vec<u8>, Header), SessionError> {
        let state_backup = self.state.clone();
        let result = self.state.encrypt_message(plaintext);
        if let Err(e) = self.persist_state() {
            self.state = state_backup;
            return Err(e);
        }
        Ok(result)
    }

    /// Decrypts a message.
    pub fn decrypt_message(
        &mut self,
        ciphertext_with_nonce: &[u8],
        header: Header,
    ) -> Result<Vec<u8>, SessionError> {
        let state_backup = self.state.clone();
        let plaintext = match self.state.decrypt_message(ciphertext_with_nonce, header) {
            Ok(pt) => pt,
            Err(e) => {
                self.state = state_backup;
                return Err(e.into());
            }
        };
        if let Err(e) = self.persist_state() {
            self.state = state_backup;
            return Err(e);
        }
        Ok(plaintext)
    }

    fn persist_state(&mut self) -> Result<(), SessionError> {
        let data = state_to_data(&self.state);
        self.store
            .save_state(&self.conversation_id, &data)
            .map_err(|e| map_store_error(e, &self.conversation_id))?;
        self.store
            .clear_skipped_keys(&self.conversation_id)
            .map_err(|e| map_store_error(e, &self.conversation_id))?;
        for key in get_skipped_keys(&self.state) {
            self.store
                .add_skipped_key(&self.conversation_id, key)
                .map_err(|e| map_store_error(e, &self.conversation_id))?;
        }
        Ok(())
    }

    pub fn state(&self) -> &RatchetState<D> {
        &self.state
    }

    pub fn conversation_id(&self) -> &str {
        &self.conversation_id
    }

    pub fn save(&mut self) -> Result<(), SessionError> {
        self.persist_state()
    }

    pub fn msg_send(&self) -> u32 {
        self.state.msg_send
    }

    pub fn msg_recv(&self) -> u32 {
        self.state.msg_recv
    }

    pub fn into_store(self) -> S {
        self.store
    }
}

fn state_to_data<D: HkdfInfo>(state: &RatchetState<D>) -> RatchetStateData {
    RatchetStateData {
        root_key: state.root_key,
        sending_chain: state.sending_chain,
        receiving_chain: state.receiving_chain,
        dh_self: state.dh_self.clone(),
        dh_remote: state.dh_remote.map(|pk| pk.to_bytes()),
        msg_send: state.msg_send,
        msg_recv: state.msg_recv,
        prev_chain_len: state.prev_chain_len,
    }
}

fn state_from_data<D: HkdfInfo + Clone>(
    data: RatchetStateData,
    skipped_keys: Vec<SkippedMessageKey>,
) -> RatchetState<D> {
    let skipped_map = skipped_keys
        .into_iter()
        .map(|sk| {
            let pk = PublicKey::from(sk.id.public_key);
            ((pk, sk.id.msg_num), sk.message_key)
        })
        .collect::<HashMap<_, _>>();

    RatchetState {
        root_key: data.root_key,
        sending_chain: data.sending_chain,
        receiving_chain: data.receiving_chain,
        dh_self: data.dh_self,
        dh_remote: data.dh_remote.map(PublicKey::from),
        msg_send: data.msg_send,
        msg_recv: data.msg_recv,
        prev_chain_len: data.prev_chain_len,
        skipped_keys: skipped_map,
        _domain: PhantomData,
    }
}

fn get_skipped_keys<D: HkdfInfo>(state: &RatchetState<D>) -> Vec<SkippedMessageKey> {
    state
        .skipped_keys
        .iter()
        .map(|((pk, msg_num), mk)| SkippedMessageKey {
            id: SkippedKeyId {
                public_key: pk.to_bytes(),
                msg_num: *msg_num,
            },
            message_key: *mk,
        })
        .collect()
}

fn map_store_error(e: StoreError, conversation_id: &str) -> SessionError {
    match e {
        StoreError::NotFound(_) => SessionError::ConvNotFound(conversation_id.to_string()),
        StoreError::AlreadyExists(_) => {
            SessionError::ConvAlreadyExists(conversation_id.to_string())
        }
        StoreError::Storage(s) => SessionError::StorageError(s),
        StoreError::Serialization(s) => SessionError::DeserializationFailed(s),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{hkdf::DefaultDomain, storage::EphemeralStore};

    #[test]
    fn test_session_create_and_open() {
        let store = EphemeralStore::new();
        let shared_secret = [0x42; 32];
        let bob_keypair = InstallationKeyPair::generate();
        let alice: RatchetState<DefaultDomain> =
            RatchetState::init_sender(shared_secret, bob_keypair.public().clone());

        let session = RatchetSession::create(store, "conv1", alice).unwrap();
        assert_eq!(session.conversation_id(), "conv1");

        let store = session.into_store();
        let session: RatchetSession<_, DefaultDomain> =
            RatchetSession::open(store, "conv1").unwrap();
        assert_eq!(session.state().msg_send, 0);
    }

    #[test]
    fn test_session_encrypt_persists() {
        let store = EphemeralStore::new();
        let shared_secret = [0x42; 32];
        let bob_keypair = InstallationKeyPair::generate();
        let alice: RatchetState<DefaultDomain> =
            RatchetState::init_sender(shared_secret, bob_keypair.public().clone());

        let mut session = RatchetSession::create(store, "conv1", alice).unwrap();
        session.encrypt_message(b"Hello").unwrap();
        assert_eq!(session.state().msg_send, 1);

        let store = session.into_store();
        let session: RatchetSession<_, DefaultDomain> =
            RatchetSession::open(store, "conv1").unwrap();
        assert_eq!(session.state().msg_send, 1);
    }
}
