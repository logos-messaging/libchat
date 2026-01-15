use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce as ChaChaNonce,
    aead::{Aead, KeyInit},
};

use crate::types::{MessageKey, Nonce};

/// Encrypts plaintext with the given key and AAD.
///
/// # Arguments
///
/// * `message_key` - The message key.
/// * `plaintext` - The plaintext to encrypt.
/// * `aad` - The additional authenticated data.
///
/// # Returns
///
/// A tuple containing the ciphertext and the randomly generated nonce.
pub fn encrypt(message_key: &MessageKey, plaintext: &[u8], aad: &[u8]) -> (Vec<u8>, Nonce) {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(message_key));
    let nonce = rand::random::<Nonce>();
    let ciphertext = cipher
        .encrypt(
            ChaChaNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("encryption failure");
    (ciphertext, nonce)
}

/// Decrypts ciphertext with the given key, nonce, and AAD.
///
/// # Arguments
///
/// * `message_key` - The message key.
/// * `ciphertext` - The ciphertext to decrypt.
/// * `nonce` - The nonce used for encryption.
/// * `aad` - The additional authenticated data.
///
/// # Returns
///
/// Ok(plaintext) on success, Err on authentication or decryption failure.
pub fn decrypt(
    message_key: &MessageKey,
    ciphertext: &[u8],
    nonce: &Nonce,
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(message_key));
    cipher
        .decrypt(
            ChaChaNonce::from_slice(nonce),
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "Decryption failed: invalid ciphertext, nonce, key, or AAD".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip_no_aad() {
        let message_key = rand::random::<[u8; 32]>();
        let plaintext = b"Hello, this is a test message!";
        let aad = b""; // Empty AAD

        let (ciphertext, nonce) = encrypt(&message_key, plaintext, aad);

        let decrypted = decrypt(&message_key, &ciphertext, &nonce, aad);

        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_with_aad() {
        let message_key = rand::random::<[u8; 32]>();

        let plaintext = b"Secret payload";
        let aad = b"public header data";

        let (ciphertext, nonce) = encrypt(&message_key, plaintext, aad);

        let decrypted = decrypt(&message_key, &ciphertext, &nonce, aad);

        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let message_key = rand::random::<[u8; 32]>();

        let plaintext = b"Important data";
        let aad = b"metadata";

        let (mut ciphertext, nonce) = encrypt(&message_key, plaintext, aad);

        // Tamper with the ciphertext
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }

        let result = decrypt(&message_key, &ciphertext, &nonce, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_aad_fails() {
        let message_key = rand::random::<[u8; 32]>();

        let plaintext = b"Data";
        let correct_aad = b"correct AAD";
        let wrong_aad = b"wrong AAD";

        let (ciphertext, nonce) = encrypt(&message_key, plaintext, correct_aad);

        let result = decrypt(&message_key, &ciphertext, &nonce, wrong_aad);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let correct_key = rand::random::<[u8; 32]>();

        let mut wrong_key = correct_key;
        wrong_key[0] ^= 0xFF; // Flip one bit

        let plaintext = b"Test";
        let aad = b"";

        let (ciphertext, nonce) = encrypt(&correct_key, plaintext, aad);

        let result = decrypt(&wrong_key, &ciphertext, &nonce, aad);

        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let message_key = [0u8; 32];
        let plaintext = b"";
        let aad = b"some aad";

        let (ciphertext, nonce) = encrypt(&message_key, plaintext, aad);
        // Ciphertext should be exactly 16 bytes (the Poly1305 tag) for empty message
        assert_eq!(ciphertext.len(), 16);

        let decrypted = decrypt(&message_key, &ciphertext, &nonce, aad);

        assert!(decrypted.is_ok());
        assert_eq!(decrypted.unwrap(), plaintext);
    }
}
