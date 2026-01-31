use crypto::PrivateKey32;
use safer_ffi::prelude::*;

#[derive_ReprC]
#[repr(opaque)]
pub struct FFIInstallationKeyPair(pub(crate) PrivateKey32);

#[ffi_export]
fn installation_key_pair_generate() -> repr_c::Box<FFIInstallationKeyPair> {
    Box::new(FFIInstallationKeyPair(PrivateKey32::random())).into()
}

#[ffi_export]
fn installation_key_pair_public(keypair: &FFIInstallationKeyPair) -> [u8; 32] {
    keypair.0.public_key().to_bytes()
}

#[ffi_export]
fn installation_key_pair_destroy(keypair: repr_c::Box<FFIInstallationKeyPair>) {
    drop(keypair)
}
