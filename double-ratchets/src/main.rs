use crate::{dhkey::DhKeyPair, kdf::kdf_root, state::RatchetState};

mod dhkey;
mod encryption;
mod kdf;
mod state;

fn main() {
    // === Initial shared secret (X3DH / prekey result in real systems) ===
    let initial_root_key = [42u8; 32];

    // === Initial DH keys ===
    let alice_dh = DhKeyPair::generate();
    let bob_dh = DhKeyPair::generate();

    // === Initial DH agreement ===
    let alice_dh_out = alice_dh.dh(&bob_dh.public);
    let bob_dh_out = bob_dh.dh(&alice_dh.public);
    assert_eq!(alice_dh_out, bob_dh_out);

    let (alice_root, alice_chain) = kdf_root(&initial_root_key, &alice_dh_out);
    let (bob_root, bob_chain) = kdf_root(&initial_root_key, &bob_dh_out);

    // === Initialize ratchets ===
    let mut alice = RatchetState {
        root_key: alice_root,
        sending_chain: Some(alice_chain),
        receiving_chain: None,
        dh_self: alice_dh,
        dh_remote: Some(bob_dh.public),
    };

    let mut bob = RatchetState {
        root_key: bob_root,
        sending_chain: None,
        receiving_chain: Some(bob_chain),
        dh_self: bob_dh,
        dh_remote: Some(alice.dh_self.public),
    };

    // === Alice sends message ===
    let (ciphertext, nonce, header) = alice.encrypt_message(b"Hello Bob!");

    // === Bob receives ===
    let plaintext = bob.decrypt_message(&ciphertext, &nonce, header);
    println!("Bob received: {}", String::from_utf8_lossy(&plaintext));

    // === Bob replies (triggers DH ratchet) ===
    let (ciphertext, nonce, header) = bob.encrypt_message(b"Hi Alice!");

    let plaintext = alice.decrypt_message(&ciphertext, &nonce, header);
    println!("Alice received: {}", String::from_utf8_lossy(&plaintext));
}
