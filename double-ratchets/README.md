# Double Ratchets

This library provides an implementation of the Double Ratchet algorithm.

## Usage

```rust
let shared_secret = [42u8; 32];
let bob_dh = DhKeyPair::generate();

let mut alice = RatchetState::init_sender(shared_secret, bob_dh.public);
let mut bob = RatchetState::init_receiver(shared_secret, bob_dh);

let (ciphertext, header) = alice.encrypt_message(b"Hello Bob!");
let plaintext = bob.decrypt_message(&ciphertext, header);
```

Run examples,

```
cargo run --example double_ratchet_basic
```
