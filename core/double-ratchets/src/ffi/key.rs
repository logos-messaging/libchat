use safer_ffi::prelude::*;

use crate::InstallationKeyPair;

#[derive_ReprC]
#[repr(opaque)]
pub struct FFIInstallationKeyPair(pub(crate) InstallationKeyPair);

#[ffi_export]
fn installation_key_pair_generate() -> repr_c::Box<FFIInstallationKeyPair> {
    Box::new(FFIInstallationKeyPair(InstallationKeyPair::generate())).into()
}

#[ffi_export]
fn installation_key_pair_public(keypair: &FFIInstallationKeyPair) -> [u8; 32] {
    keypair.0.public().clone().to_bytes()
}

#[ffi_export]
fn installation_key_pair_destroy(keypair: repr_c::Box<FFIInstallationKeyPair>) {
    drop(keypair)
}
