//! Storage type conversions between ratchet state and storage records.

use storage::{RatchetStateRecord, SkippedKeyRecord};

use crate::{
    hkdf::HkdfInfo,
    state::{RatchetState, SkippedKey},
};

/// Converts a `RatchetState` into a `RatchetStateRecord` for storage.
pub fn to_ratchet_record<D: HkdfInfo>(state: &RatchetState<D>) -> RatchetStateRecord {
    RatchetStateRecord {
        root_key: state.root_key,
        sending_chain: state.sending_chain,
        receiving_chain: state.receiving_chain,
        dh_self_secret: *state.dh_self.secret_bytes(),
        dh_remote: state.dh_remote.map(|pk| pk.to_bytes()),
        msg_send: state.msg_send,
        msg_recv: state.msg_recv,
        prev_chain_len: state.prev_chain_len,
    }
}

/// Converts a `RatchetStateRecord` and skipped keys back into a `RatchetState`.
pub fn restore_ratchet_state<D: HkdfInfo>(
    record: RatchetStateRecord,
    skipped_keys: Vec<SkippedKeyRecord>,
) -> RatchetState<D> {
    use crate::keypair::InstallationKeyPair;
    use std::collections::HashMap;
    use std::marker::PhantomData;
    use x25519_dalek::PublicKey;

    let dh_self = InstallationKeyPair::from_secret_bytes(record.dh_self_secret);
    let dh_remote = record.dh_remote.map(PublicKey::from);

    let skipped: HashMap<(PublicKey, u32), crate::types::MessageKey> = skipped_keys
        .into_iter()
        .map(|sk| ((PublicKey::from(sk.public_key), sk.msg_num), sk.message_key))
        .collect();

    RatchetState {
        root_key: record.root_key,
        sending_chain: record.sending_chain,
        receiving_chain: record.receiving_chain,
        dh_self,
        dh_remote,
        msg_send: record.msg_send,
        msg_recv: record.msg_recv,
        prev_chain_len: record.prev_chain_len,
        skipped_keys: skipped,
        _domain: PhantomData,
    }
}

/// Converts skipped keys from ratchet state format to storage record format.
pub fn to_skipped_key_records(keys: &[SkippedKey]) -> Vec<SkippedKeyRecord> {
    keys.iter()
        .map(|sk| SkippedKeyRecord {
            public_key: sk.public_key,
            msg_num: sk.msg_num,
            message_key: sk.message_key,
        })
        .collect()
}
