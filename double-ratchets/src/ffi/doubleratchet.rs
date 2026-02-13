use crypto::PublicKey;
use safer_ffi::prelude::*;

use crate::{
    Header, RatchetState,
    ffi::{key::FFIInstallationKeyPair, utils::CResult},
};

#[derive_ReprC]
#[repr(opaque)]
pub struct FFIRatchetState(pub(crate) RatchetState);

#[derive_ReprC]
#[repr(opaque)]
pub struct FFIEncryptResult {
    pub ciphertext: Vec<u8>,
    pub header: Header,
}

#[ffi_export]
fn double_ratchet_init_sender(
    shared_secret: [u8; 32],
    remote_pub: [u8; 32],
) -> repr_c::Box<FFIRatchetState> {
    let state = RatchetState::init_sender(shared_secret, PublicKey::from(remote_pub));
    Box::new(FFIRatchetState(state)).into()
}

#[ffi_export]
fn double_ratchet_init_receiver(
    shared_secret: [u8; 32],
    keypair: &FFIInstallationKeyPair,
) -> repr_c::Box<FFIRatchetState> {
    let state = RatchetState::init_receiver(shared_secret, keypair.0.clone());
    Box::new(FFIRatchetState(state)).into()
}

#[ffi_export]
fn double_ratchet_encrypt_message(
    state: &mut FFIRatchetState,
    plaintext: &repr_c::Vec<u8>,
) -> repr_c::Box<FFIEncryptResult> {
    let encrypted = state.0.encrypt_message(plaintext);
    let result = FFIEncryptResult {
        ciphertext: encrypted.0,
        header: encrypted.1,
    };
    Box::new(result).into()
}

//TODO rename decrypt
#[ffi_export]
fn double_ratchet_descrypt_message(
    state: &mut FFIRatchetState,
    encrypted: &FFIEncryptResult,
) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    let decrypted = state
        .0
        .decrypt_message(&encrypted.ciphertext, encrypted.header.clone());

    match decrypted {
        Ok(plaintext) => CResult {
            ok: Some(plaintext.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
fn ratchet_state_destroy(state: repr_c::Box<FFIRatchetState>) {
    drop(state)
}

#[ffi_export]
fn encrypt_result_destroy(result: repr_c::Box<FFIEncryptResult>) {
    drop(result)
}
