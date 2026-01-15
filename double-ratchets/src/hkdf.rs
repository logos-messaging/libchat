use blake2::{
    Blake2b512, Blake2bMac,
    digest::{FixedOutput, consts::U32},
};
use hkdf::SimpleHkdf;

use crate::types::{ChainKey, MessageKey, RootKey, SharedSecret};

type Blake2bMac256 = Blake2bMac<U32>;

/// Application-level domain separation for root key derivation using HKDF.
/// This separates different applications/protocols using the same primitives.
pub trait HkdfInfo {
    const ROOT_KEY: &'static [u8];
}

/// Default implementation for standalone Double Ratchet
#[derive(Clone, Copy)]
pub struct DefaultDomain;

impl HkdfInfo for DefaultDomain {
    const ROOT_KEY: &'static [u8] = b"DoubleRatchetRootKey";
}

/// Domain for PrivateV1 protocol
#[derive(Clone, Copy)]
pub struct PrivateV1Domain;

impl HkdfInfo for PrivateV1Domain {
    const ROOT_KEY: &'static [u8] = b"PrivateV1RootKey";
}

/// Spec-level domain separation constants for Double Ratchet chain KDF.
/// These are fixed by the Double Ratchet specification and use BLAKE2's
/// personalization parameter for domain separation.
mod chain_kdf {
    /// Personalization string for deriving message keys
    pub const MESSAGE_KEY_PERSONAL: &[u8] = b"mk";
    /// Personalization string for deriving chain keys
    pub const CHAIN_KEY_PERSONAL: &[u8] = b"ck";
}

/// Derive a new root key and chain key from the given root key and Diffie-Hellman shared secret.
///
/// # Arguments
///
/// * `root` - The current root key.
/// * `dh` - The Diffie-Hellman shared secret.
///
/// # Returns
///
/// A tuple containing the new root key and chain key.
pub fn kdf_root<D: HkdfInfo>(root: &RootKey, dh: &SharedSecret) -> (RootKey, ChainKey) {
    let hk = SimpleHkdf::<Blake2b512>::new(Some(root), dh);

    let mut okm = [0u8; 64];
    hk.expand(D::ROOT_KEY, &mut okm).unwrap();

    let new_root = okm[..32].try_into().unwrap();
    let chain = okm[32..].try_into().unwrap();
    (new_root, chain)
}

/// Derive a new chain key and message key from the given chain key.
///
/// # Arguments
///
/// * `chain` - The current chain key.
///
/// # Returns
///
/// A tuple containing the new chain key and message key.
pub fn kdf_chain(chain: &ChainKey) -> (ChainKey, MessageKey) {
    // Derive message key
    let msg_key_mac = Blake2bMac256::new_with_salt_and_personal(
        chain,
        &[], // No salt - input already has high entropy
        chain_kdf::MESSAGE_KEY_PERSONAL,
    )
    .unwrap();
    let msg_key: MessageKey = msg_key_mac.finalize_fixed().into();

    // Derive next chain key
    let chain_key_mac = Blake2bMac256::new_with_salt_and_personal(
        chain,
        &[], // No salt - input already has high entropy
        chain_kdf::CHAIN_KEY_PERSONAL,
    )
    .unwrap();
    let next_chain: ChainKey = chain_key_mac.finalize_fixed().into();

    (next_chain, msg_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_root_deterministic_output() {
        // Fixed inputs for reproducible testing
        let root = [0x11; 32];
        let dh = [0x22; 32];

        let (new_root, chain) = kdf_root::<DefaultDomain>(&root, &dh);

        // These values can be verified manually or against a reference implementation
        // (e.g., Signal's spec or another HKDF test vector)
        let expected_new_root = [
            252, 149, 120, 209, 39, 209, 254, 187, 230, 101, 10, 72, 153, 242, 102, 43, 14, 175,
            152, 122, 188, 117, 116, 153, 169, 244, 84, 239, 172, 228, 75, 158,
        ];
        let expected_chain = [
            179, 178, 244, 176, 145, 144, 55, 144, 149, 119, 47, 208, 154, 230, 78, 67, 42, 200,
            218, 89, 199, 216, 138, 37, 93, 161, 78, 206, 85, 120, 52, 212,
        ];

        assert_eq!(new_root, expected_new_root);
        assert_eq!(chain, expected_chain);

        // Run again to ensure determinism
        let (new_root2, chain2) = kdf_root::<DefaultDomain>(&root, &dh);
        assert_eq!(new_root, new_root2);
        assert_eq!(chain, chain2);
    }

    #[test]
    fn test_kdf_chain_sequence() {
        let initial_chain = [0xaa; 32];

        let (msg_key1, chain2) = kdf_chain(&initial_chain);
        let (msg_key2, chain3) = kdf_chain(&chain2);
        let (msg_key3, chain4) = kdf_chain(&chain3);

        // All message keys should be different
        assert_ne!(msg_key1, msg_key2);
        assert_ne!(msg_key2, msg_key3);
        assert_ne!(msg_key1, msg_key3);

        // Chain keys should evolve
        assert_ne!(initial_chain, chain2);
        assert_ne!(chain2, chain3);
        assert_ne!(chain3, chain4);
    }

    #[test]
    fn test_kdf_chain_deterministic() {
        let chain = [0xff; 32];

        let (next_chain, msg_key) = kdf_chain(&chain);

        let expected_msg_key = [
            218, 132, 123, 191, 200, 122, 53, 45, 0, 113, 160, 14, 116, 47, 124, 193, 218, 213, 86,
            3, 71, 95, 150, 77, 148, 244, 21, 36, 218, 51, 69, 118,
        ];
        let expected_next_chain = [
            150, 245, 67, 74, 243, 9, 1, 244, 133, 19, 37, 213, 11, 72, 130, 183, 155, 1, 154, 52,
            56, 108, 193, 167, 33, 208, 190, 16, 172, 250, 168, 71,
        ];

        assert_eq!(msg_key, expected_msg_key);
        assert_eq!(next_chain, expected_next_chain);
    }

    #[test]
    fn test_full_ratchet_step() {
        // Simulate one full root update + chain step
        let root = [0x01; 32];
        let dh_out = [0x02; 32];

        let (new_root, sending_chain) = kdf_root::<DefaultDomain>(&root, &dh_out);

        let (msg_key, next_chain) = kdf_chain(&sending_chain);

        // All outputs should be cryptographically distinct and non-zero
        assert_ne!(new_root, root);
        assert_ne!(sending_chain, [0u8; 32]);
        assert_ne!(msg_key, [0u8; 32]);
        assert_ne!(next_chain, sending_chain);

        // Message key should not leak chain key info
        assert_ne!(msg_key, sending_chain);
        assert_ne!(msg_key, next_chain);
    }

    #[test]
    fn test_different_inputs_produce_different_outputs() {
        let root1 = [0x11; 32];
        let root2 = [0x11; 32];
        let mut root2_modified = root2;
        root2_modified[0] ^= 0x01;

        let dh1 = [0x22; 32];
        let dh2 = [0x22; 32];
        let mut dh2_modified = dh2;
        dh2_modified[31] ^= 0x80;

        let (out1, _) = kdf_root::<DefaultDomain>(&root1, &dh1);
        let (out2, _) = kdf_root::<DefaultDomain>(&root2_modified, &dh1);
        let (out3, _) = kdf_root::<DefaultDomain>(&root1, &dh2_modified);

        assert_ne!(out1, out2); // Changing root changes output
        assert_ne!(out1, out3); // Changing DH changes output
    }
}
