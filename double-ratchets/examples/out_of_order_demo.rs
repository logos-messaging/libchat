//! Demonstrates out-of-order message handling with skipped keys persistence.
//!
//! Run with: cargo run --example out_of_order_demo -p double-ratchets

use double_ratchets::{InstallationKeyPair, RatchetSession, RatchetStorage};
use tempfile::NamedTempFile;

fn main() {
    println!("=== Out-of-Order Message Handling Demo ===\n");

    let alice_db_file = NamedTempFile::new().unwrap();
    let alice_db_path = alice_db_file.path().to_str().unwrap();
    let bob_db_file = NamedTempFile::new().unwrap();
    let bob_db_path = bob_db_file.path().to_str().unwrap();

    let shared_secret = [0x42u8; 32];
    let bob_keypair = InstallationKeyPair::generate();
    let bob_public = *bob_keypair.public();

    let conv_id = "out_of_order_conv";
    let encryption_key = "super-secret-key-123!";

    // Collect messages for out-of-order delivery
    let mut messages: Vec<(Vec<u8>, double_ratchets::Header)> = Vec::new();

    // Phase 1: Alice sends 5 messages, Bob receives 1, 3, 5 (skipping 2, 4)
    {
        let mut alice_storage = RatchetStorage::new(alice_db_path, encryption_key)
            .expect("Failed to create Alice storage");
        let mut bob_storage =
            RatchetStorage::new(bob_db_path, encryption_key).expect("Failed to create Bob storage");

        let mut alice_session: RatchetSession = RatchetSession::create_sender_session(
            &mut alice_storage,
            conv_id,
            shared_secret,
            bob_public,
        )
        .unwrap();

        let mut bob_session: RatchetSession = RatchetSession::create_receiver_session(
            &mut bob_storage,
            conv_id,
            shared_secret,
            bob_keypair,
        )
        .unwrap();

        println!("  Sessions created for Alice and Bob");

        // Alice sends 5 messages
        for i in 1..=5 {
            let msg = format!("Message #{}", i);
            let (ct, header) = alice_session.encrypt_message(msg.as_bytes()).unwrap();
            messages.push((ct, header));
        }
        println!("  Alice sent 5 messages");

        // Bob receives 1, 3, 5 (skips 2, 4)
        for &idx in &[0, 2, 4] {
            let (ct, header) = &messages[idx];
            bob_session.decrypt_message(ct, header.clone()).unwrap();
        }

        println!(
            "  Bob received 1,3,5. Skipped keys stored: {}",
            bob_session.state().skipped_keys.len()
        );
    }

    // Phase 2: Simulate app restart by reopening storage
    println!("\n  Simulating app restart...");
    {
        let mut bob_storage =
            RatchetStorage::new(bob_db_path, encryption_key).expect("Failed to reopen Bob storage");

        let bob_session: RatchetSession = RatchetSession::open(&mut bob_storage, conv_id).unwrap();
        println!(
            "  After restart, Bob's skipped_keys: {}",
            bob_session.state().skipped_keys.len()
        );
    }

    // Phase 3: Bob receives the delayed messages
    println!("\nBob receives delayed message 2...");
    let (ct4, header4) = messages[3].clone(); // Save for replay test
    {
        let mut bob_storage =
            RatchetStorage::new(bob_db_path, encryption_key).expect("Failed to open Bob storage");

        let mut bob_session: RatchetSession =
            RatchetSession::open(&mut bob_storage, conv_id).unwrap();

        let (ct, header) = &messages[1];
        let pt = bob_session.decrypt_message(ct, header.clone()).unwrap();
        println!("  Received: \"{}\"", String::from_utf8_lossy(&pt));
        println!(
            "  Remaining skipped_keys: {}",
            bob_session.state().skipped_keys.len()
        );
    }

    println!("\nBob receives delayed message 4...");
    {
        let mut bob_storage =
            RatchetStorage::new(bob_db_path, encryption_key).expect("Failed to open Bob storage");

        let mut bob_session: RatchetSession =
            RatchetSession::open(&mut bob_storage, conv_id).unwrap();

        let pt = bob_session.decrypt_message(&ct4, header4.clone()).unwrap();
        println!("  Received: \"{}\"", String::from_utf8_lossy(&pt));
        println!(
            "  Remaining skipped_keys: {}",
            bob_session.state().skipped_keys.len()
        );
    }

    // Phase 4: Demonstrate replay protection
    println!("\n--- Replay Protection Demo ---");
    println!("Trying to decrypt message 4 again (should fail)...");
    {
        let mut bob_storage =
            RatchetStorage::new(bob_db_path, encryption_key).expect("Failed to open Bob storage");

        let mut bob_session: RatchetSession =
            RatchetSession::open(&mut bob_storage, conv_id).unwrap();

        match bob_session.decrypt_message(&ct4, header4) {
            Ok(_) => println!("  ERROR: Replay attack succeeded!"),
            Err(e) => println!("  Correctly rejected: {}", e),
        }
    }

    // Cleanup
    let _ = std::fs::remove_file(alice_db_path);
    let _ = std::fs::remove_file(bob_db_path);

    println!("\n=== Demo Complete ===");
}
