//! Demonstrates out-of-order message handling with skipped keys persistence.
//!
//! Run with: cargo run --example out_of_order_demo --features storage

#[cfg(feature = "storage")]
use double_ratchets::{
    InstallationKeyPair, RatchetState, RatchetStorage, StorageConfig, hkdf::DefaultDomain,
    state::Header,
};

fn main() {
    println!("=== Out-of-Order Message Handling Demo (skipped - enable 'storage' feature) ===\n");

    #[cfg(feature = "storage")]
    run_demo();
}

#[cfg(feature = "storage")]
fn run_demo() {
    let mut storage =
        RatchetStorage::with_config(StorageConfig::InMemory).expect("Failed to create storage");

    // Setup
    let shared_secret = [0x42u8; 32];
    let bob_keypair = InstallationKeyPair::generate();

    let alice_state: RatchetState<DefaultDomain> =
        RatchetState::init_sender(shared_secret, bob_keypair.public().clone());
    let bob_state: RatchetState<DefaultDomain> =
        RatchetState::init_receiver(shared_secret, bob_keypair);

    storage.save("alice", &alice_state).unwrap();
    storage.save("bob", &bob_state).unwrap();

    // === Alice sends 5 messages ===
    println!("Alice sends 5 messages...");
    let mut messages: Vec<(Vec<u8>, Header)> = Vec::new();

    for i in 1..=5 {
        let mut alice: RatchetState<DefaultDomain> = storage.load("alice").unwrap();
        let msg = format!("Message #{}", i);
        let (ct, header) = alice.encrypt_message(msg.as_bytes());
        storage.save("alice", &alice).unwrap();
        messages.push((ct, header));
        println!("  Sent: \"{}\"", msg);
    }

    // === Bob receives messages out of order: 1, 3, 5 ===
    println!("\nBob receives messages 1, 3, 5 (out of order)...");

    for &idx in &[0, 2, 4] {
        let mut bob: RatchetState<DefaultDomain> = storage.load("bob").unwrap();
        let (ct, header) = &messages[idx];
        let pt = bob
            .decrypt_message(ct, header.clone())
            .expect("Decrypt failed");
        storage.save("bob", &bob).unwrap();
        println!("  Received: \"{}\"", String::from_utf8_lossy(&pt));
    }

    let bob: RatchetState<DefaultDomain> = storage.load("bob").unwrap();
    println!("\nBob's skipped_keys count: {}", bob.skipped_keys.len());
    println!("  (Messages 2 and 4 keys are stored for later)");

    // === Simulate Bob's app restart ===
    println!("\n--- Simulating Bob's app restart ---");
    drop(storage);

    // In-memory storage doesn't persist across restarts.
    // Use file storage to properly demonstrate persistence:
    println!("  (Using file storage to demonstrate real persistence)");
    if let Err(e) = std::fs::create_dir_all("./tmp") {
        eprintln!("Failed to create tmp directory: {}", e);
        return; // Or handle as needed
    }
    let db_path = "./tmp/out_of_order_demo.db";
    let _ = std::fs::remove_file(db_path);

    // Redo with file storage
    let mut storage = RatchetStorage::with_config(StorageConfig::File(db_path.to_string()))
        .expect("Failed to create storage");

    // Re-setup
    let bob_keypair = InstallationKeyPair::generate();
    let alice_state: RatchetState<DefaultDomain> =
        RatchetState::init_sender(shared_secret, bob_keypair.public().clone());
    let bob_state: RatchetState<DefaultDomain> =
        RatchetState::init_receiver(shared_secret, bob_keypair);

    storage.save("alice", &alice_state).unwrap();
    storage.save("bob", &bob_state).unwrap();

    // Alice sends 5 messages
    let mut messages: Vec<(Vec<u8>, Header)> = Vec::new();
    for i in 1..=5 {
        let mut alice: RatchetState<DefaultDomain> = storage.load("alice").unwrap();
        let msg = format!("Message #{}", i);
        let (ct, header) = alice.encrypt_message(msg.as_bytes());
        storage.save("alice", &alice).unwrap();
        messages.push((ct, header));
    }
    println!("  Alice sent 5 messages");

    // Bob receives 1, 3, 5 (skips 2, 4)
    for &idx in &[0, 2, 4] {
        let mut bob: RatchetState<DefaultDomain> = storage.load("bob").unwrap();
        let (ct, header) = &messages[idx];
        bob.decrypt_message(ct, header.clone()).unwrap();
        storage.save("bob", &bob).unwrap();
    }

    let bob: RatchetState<DefaultDomain> = storage.load("bob").unwrap();
    println!(
        "  Bob received 1,3,5. Skipped keys stored: {}",
        bob.skipped_keys.len()
    );

    // Close and reopen storage (simulating app restart)
    drop(storage);
    let mut storage =
        RatchetStorage::with_config(StorageConfig::File(db_path.to_string())).expect("Failed to reopen");

    let bob: RatchetState<DefaultDomain> = storage.load("bob").unwrap();
    println!(
        "\n  After restart, Bob's skipped_keys: {}",
        bob.skipped_keys.len()
    );

    // === Now Bob receives the delayed messages ===
    println!("\nBob receives delayed message 2...");
    {
        let mut bob: RatchetState<DefaultDomain> = storage.load("bob").unwrap();
        let (ct, header) = &messages[1];
        let pt = bob.decrypt_message(ct, header.clone()).unwrap();
        storage.save("bob", &bob).unwrap();
        println!("  Received: \"{}\"", String::from_utf8_lossy(&pt));
        println!("  Remaining skipped_keys: {}", bob.skipped_keys.len());
    }

    println!("\nBob receives delayed message 4...");
    let (ct4, header4) = messages[3].clone();
    {
        let mut bob: RatchetState<DefaultDomain> = storage.load("bob").unwrap();
        let pt = bob.decrypt_message(&ct4, header4.clone()).unwrap();
        storage.save("bob", &bob).unwrap();
        println!("  Received: \"{}\"", String::from_utf8_lossy(&pt));
        println!("  Remaining skipped_keys: {}", bob.skipped_keys.len());
    }

    // === Demonstrate replay protection ===
    println!("\n--- Replay Protection Demo ---");
    println!("Trying to decrypt message 4 again (should fail)...");

    {
        let mut bob: RatchetState<DefaultDomain> = storage.load("bob").unwrap();
        match bob.decrypt_message(&ct4, header4) {
            Ok(_) => println!("  ERROR: Replay attack succeeded!"),
            Err(e) => println!("  Correctly rejected: {:?}", e),
        }
    }

    // Cleanup
    let _ = std::fs::remove_file(db_path);

    println!("\n=== Demo Complete ===");
}
