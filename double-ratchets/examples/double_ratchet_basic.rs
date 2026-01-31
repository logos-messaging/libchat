use crypto::PrivateKey32;
use double_ratchets::{RatchetState, hkdf::PrivateV1Domain};

fn main() {
    // === Initial shared secret (X3DH / prekey result in real systems) ===
    let shared_secret = [42u8; 32];

    let bob_dh = PrivateKey32::random();

    let mut alice: RatchetState<PrivateV1Domain> =
        RatchetState::init_sender(shared_secret, bob_dh.public_key());
    let mut bob: RatchetState<PrivateV1Domain> = RatchetState::init_receiver(shared_secret, bob_dh);

    let (ciphertext, header) = alice.encrypt_message(b"Hello Bob!");

    // === Bob receives ===
    let plaintext = bob.decrypt_message(&ciphertext, header);
    println!(
        "Bob received: {}",
        String::from_utf8_lossy(&plaintext.unwrap())
    );

    // === Bob replies (triggers DH ratchet) ===
    let (ciphertext, header) = bob.encrypt_message(b"Hi Alice!");

    let plaintext = alice.decrypt_message(&ciphertext, header);
    println!(
        "Alice received: {}",
        String::from_utf8_lossy(&plaintext.unwrap())
    );
}
