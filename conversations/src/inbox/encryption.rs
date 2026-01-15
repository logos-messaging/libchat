use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
/// This performs an x3dh on initialization and then provides encryption using ChachaPoly
use crypto::{PrekeyBundle, X3Handshake};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

#[derive(Debug)]
pub enum InboxEncryptionError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidMessage,
    KeyDerivationFailed,
    NonceExhausted,
}

/// Represents an encrypted session initialized with X3DH
pub struct InboxEncryption {
    /// Root key derived from X3DH
    secret_key: [u8; 32],
    symmetric_encryption_key: [u8; 32],
    _msg_count: u32,
    n: u64,
}

impl InboxEncryption {
    /// Initialize as the initiator (sender) using X3DH
    ///
    /// # Arguments
    /// * `identity_keypair` - Your long-term identity key pair
    /// * `recipient_bundle` - Recipient's prekey bundle
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    /// A tuple of (InboxEncryption, ephemeral_public_key) to send to recipient
    pub fn init_as_initiator<R: RngCore + CryptoRng>(
        identity_keypair: &StaticSecret,
        recipient_bundle: &PrekeyBundle,
        rng: &mut R,
    ) -> (Self, PublicKey) {
        // Perform X3DH to get shared secret
        let (shared_secret, ephemeral_public) =
            X3Handshake::initator(identity_keypair, recipient_bundle, rng);

        // Derive root key and initial chain keys from shared secret
        // As initiator, we use chain0 for sending, chain1 for receiving
        let (secret_key, symmetric_encryption_key) =
            Self::derive_keys_from_shared_secret(&shared_secret);

        let session = Self {
            secret_key,
            symmetric_encryption_key,
            _msg_count: 0,
            n: 0,
        };

        (session, ephemeral_public)
    }

    /// Initialize as the responder (receiver) using X3DH
    ///
    /// # Arguments
    /// * `identity_keypair` - Your long-term identity key pair
    /// * `signed_prekey` - Your signed prekey (private)
    /// * `onetime_prekey` - Your one-time prekey (private, if used)
    /// * `initiator_identity` - Initiator's identity public key
    /// * `initiator_ephemeral` - Initiator's ephemeral public key
    pub fn init_as_responder(
        identity_keypair: &StaticSecret,
        signed_prekey: &StaticSecret,
        onetime_prekey: Option<&StaticSecret>,
        initiator_identity: &PublicKey,
        initiator_ephemeral: &PublicKey,
    ) -> Self {
        // Perform X3DH to get shared secret
        let shared_secret = X3Handshake::responder(
            identity_keypair,
            signed_prekey,
            onetime_prekey,
            initiator_identity,
            initiator_ephemeral,
        );

        // Derive root key and initial chain keys from shared secret
        let (secret_key, symmetric_encryption_key) =
            Self::derive_keys_from_shared_secret(&shared_secret);

        Self {
            secret_key,
            symmetric_encryption_key,
            _msg_count: 0,
            n: 0,
        }
    }

    /// Derive root key and chain keys from X3DH shared secret
    fn derive_keys_from_shared_secret(shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(None, shared_secret);

        let mut root_key = [0u8; 32];
        hk.expand(b"InboxV1", &mut root_key)
            .expect("32 bytes is valid HKDF output length");

        let mut encryption_key = [0u8; 32];
        hk.expand(b"InboxV1-Encryption", &mut encryption_key)
            .expect("32 bytes is valid HKDF output length");

        (root_key, encryption_key)
    }

    /// Derive a message key from the encryption key and nonce
    fn derive_message_key(encryption_key: &[u8; 32], nonce: u64) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, encryption_key);
        let mut message_key = [0u8; 32];
        let info = format!("InboxV1-MsgKey-{}", nonce);

        println!("DMK1  {:?}", info.as_bytes(),);
        println!("DMK2  {:?}", encryption_key);
        println!("DMK3  {:?}", message_key);
        hk.expand(info.as_bytes(), &mut message_key)
            .expect("32 bytes is valid HKDF output length");
        message_key
    }

    /// Encrypt a message using ChaCha20-Poly1305
    ///
    /// # Arguments
    /// * `plaintext` - The message to encrypt
    ///
    /// # Returns
    /// Encrypted message (nonce + ciphertext + tag)
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, InboxEncryptionError> {
        // A Nonce must not be able to wrap around due to an overflow
        if self.n == u64::MAX {
            return Err(InboxEncryptionError::NonceExhausted);
        }

        // 1. Derive message key from encryption key and nonce
        let message_key = Self::derive_message_key(&self.symmetric_encryption_key, self.n);
        println!("MK: {:?}", self.symmetric_encryption_key);

        // 2. Create nonce from counter (8 bytes padded to 12 bytes)
        let nonce_bytes_u64 = self.n.to_le_bytes();
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..8].copy_from_slice(&nonce_bytes_u64);
        println!("Nonce: {:?}", nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 3. Encrypt plaintext with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(&message_key.into());
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| InboxEncryptionError::EncryptionFailed)?;

        // 4. Increment nonce counter
        self.n += 1;

        // 5. Return nonce + ciphertext + tag (tag is already included in ciphertext)
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        println!("Cipher: {:?}", result);
        Ok(result)
    }

    /// Decrypt a message using ChaCha20-Poly1305
    ///
    /// # Arguments
    /// * `ciphertext` - The encrypted message (nonce + ciphertext + tag)
    ///
    /// # Returns
    /// Decrypted plaintext
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, InboxEncryptionError> {
        // 1. Extract nonce, ciphertext, and tag from input
        if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
            return Err(InboxEncryptionError::InvalidMessage);
        }

        let (nonce_bytes, encrypted_data) = ciphertext.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // 2. Derive message key from encryption key and nonce counter
        let message_key = Self::derive_message_key(&self.symmetric_encryption_key, self.n);

        // 3. Decrypt ciphertext with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(&message_key.into());
        let plaintext = cipher
            .decrypt(nonce, encrypted_data)
            .map_err(|_| InboxEncryptionError::DecryptionFailed)?;

        // 4. Increment nonce counter
        self.n += 1;

        // 5. Return plaintext
        Ok(plaintext)
    }

    pub fn get_root_key(&self) -> [u8; 32] {
        self.secret_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_inbox_encryption_initialization() {
        let mut rng = OsRng;

        // Alice (initiator) generates her identity key
        let alice_identity = StaticSecret::random_from_rng(&mut rng);
        let alice_identity_pub = PublicKey::from(&alice_identity);

        // Bob (responder) generates his keys
        let bob_identity = StaticSecret::random_from_rng(&mut rng);
        let bob_signed_prekey = StaticSecret::random_from_rng(&mut rng);
        let bob_signed_prekey_pub = PublicKey::from(&bob_signed_prekey);

        // Create Bob's prekey bundle
        let bob_bundle = PrekeyBundle {
            identity_key: PublicKey::from(&bob_identity),
            signed_prekey: bob_signed_prekey_pub,
            signature: [0u8; 64],
            onetime_prekey: None,
        };

        // Alice initializes session
        let (alice_session, alice_ephemeral_pub) =
            InboxEncryption::init_as_initiator(&alice_identity, &bob_bundle, &mut rng);

        // Bob initializes session
        let bob_session = InboxEncryption::init_as_responder(
            &bob_identity,
            &bob_signed_prekey,
            None,
            &alice_identity_pub,
            &alice_ephemeral_pub,
        );

        // Both should derive the same root key
        assert_eq!(alice_session.get_root_key(), bob_session.get_root_key());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut rng = OsRng;

        // Alice (initiator) generates her identity key
        let alice_identity = StaticSecret::random_from_rng(&mut rng);
        let alice_identity_pub = PublicKey::from(&alice_identity);

        // Bob (responder) generates his keys
        let bob_identity = StaticSecret::random_from_rng(&mut rng);
        let bob_signed_prekey = StaticSecret::random_from_rng(&mut rng);
        let bob_signed_prekey_pub = PublicKey::from(&bob_signed_prekey);

        // Create Bob's prekey bundle
        let bob_bundle = PrekeyBundle {
            identity_key: PublicKey::from(&bob_identity),
            signed_prekey: bob_signed_prekey_pub,
            signature: [0u8; 64],
            onetime_prekey: None,
        };

        // Alice initializes session
        let (mut alice_session, alice_ephemeral_pub) =
            InboxEncryption::init_as_initiator(&alice_identity, &bob_bundle, &mut rng);

        // Bob initializes session
        let mut bob_session = InboxEncryption::init_as_responder(
            &bob_identity,
            &bob_signed_prekey,
            None,
            &alice_identity_pub,
            &alice_ephemeral_pub,
        );

        // Alice sends a message to Bob
        let message1 = b"Hello, Bob!";
        let encrypted1 = alice_session.encrypt(message1).unwrap();
        let decrypted1 = bob_session.decrypt(&encrypted1).unwrap();
        assert_eq!(message1, decrypted1.as_slice());

        // Bob replies to Alice
        let message2 = b"Hi Alice, how are you?";
        let encrypted2 = bob_session.encrypt(message2).unwrap();
        let decrypted2 = alice_session.decrypt(&encrypted2).unwrap();
        assert_eq!(message2, decrypted2.as_slice());

        // Multiple messages in sequence
        for i in 0..10 {
            let msg = format!("Message {}", i);
            let encrypted = alice_session.encrypt(msg.as_bytes()).unwrap();
            let decrypted = bob_session.decrypt(&encrypted).unwrap();
            assert_eq!(msg.as_bytes(), decrypted.as_slice());
        }
    }

    #[test]
    fn test_decrypt_wrong_message_fails() {
        let mut rng = OsRng;

        // Setup two sessions
        let alice_identity = StaticSecret::random_from_rng(&mut rng);
        let alice_identity_pub = PublicKey::from(&alice_identity);

        let bob_identity = StaticSecret::random_from_rng(&mut rng);
        let bob_signed_prekey = StaticSecret::random_from_rng(&mut rng);
        let bob_signed_prekey_pub = PublicKey::from(&bob_signed_prekey);

        let bob_bundle = PrekeyBundle {
            identity_key: PublicKey::from(&bob_identity),
            signed_prekey: bob_signed_prekey_pub,
            signature: [0u8; 64],
            onetime_prekey: None,
        };

        let (mut alice_session, alice_ephemeral_pub) =
            InboxEncryption::init_as_initiator(&alice_identity, &bob_bundle, &mut rng);

        let mut bob_session = InboxEncryption::init_as_responder(
            &bob_identity,
            &bob_signed_prekey,
            None,
            &alice_identity_pub,
            &alice_ephemeral_pub,
        );

        // Encrypt a message
        let message = b"Secret message";
        let mut encrypted = alice_session.encrypt(message).unwrap();

        // Tamper with the ciphertext
        encrypted[NONCE_SIZE] ^= 0xFF;

        // Decryption should fail
        let result = bob_session.decrypt(&encrypted);
        assert!(result.is_err());
    }
}
