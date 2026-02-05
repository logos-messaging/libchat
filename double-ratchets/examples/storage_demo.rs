//! Demonstrates SQLite storage for Double Ratchet state persistence.
//!
//! Run with: cargo run --example storage_demo -p double-ratchets

use double_ratchets::{InstallationKeyPair, RatchetSession, RatchetStorage};
use tempfile::NamedTempFile;

fn main() {
    println!("=== Double Ratchet Storage Demo ===\n");

    let alice_db_file = NamedTempFile::new().unwrap();
    let alice_db_path = alice_db_file.path().to_str().unwrap().to_string();
    let bob_db_file = NamedTempFile::new().unwrap();
    let bob_db_path = bob_db_file.path().to_str().unwrap().to_string();

    let encryption_key = "super-secret-key-123!";
    let conv_id = "conv1";

    // Initial conversation with encryption
    {
        let alice_storage = RatchetStorage::new(&alice_db_path, encryption_key)
            .expect("Failed to create alice encrypted storage");
        let bob_storage = RatchetStorage::new(&bob_db_path, encryption_key)
            .expect("Failed to create bob encrypted storage");
        println!(
            "  Encrypted database created at: {}, {}",
            alice_db_path, bob_db_path
        );
        run_conversation(alice_storage, bob_storage, conv_id);
    }

    // Restart with correct key
    println!("\n  Simulating restart with encryption key...");
    {
        let alice_storage = RatchetStorage::new(&alice_db_path, encryption_key)
            .expect("Failed to create alice encrypted storage");
        let bob_storage = RatchetStorage::new(&bob_db_path, encryption_key)
            .expect("Failed to create bob encrypted storage");
        continue_after_restart(alice_storage, bob_storage, conv_id);
    }

    let _ = std::fs::remove_file(&alice_db_path);
    let _ = std::fs::remove_file(&bob_db_path);
}

/// Simulates a conversation between Alice and Bob.
/// Each party saves/loads state from storage for each operation.
fn run_conversation(alice_storage: RatchetStorage, bob_storage: RatchetStorage, conv_id: &str) {
    // === Setup: Simulate X3DH key exchange ===
    let shared_secret = [0x42u8; 32]; // In reality, this comes from X3DH
    let bob_keypair = InstallationKeyPair::generate();

    let mut alice_session: RatchetSession = RatchetSession::create_sender_session(
        alice_storage,
        conv_id,
        shared_secret,
        bob_keypair.public().clone(),
    )
    .unwrap();

    let mut bob_session: RatchetSession =
        RatchetSession::create_receiver_session(bob_storage, conv_id, shared_secret, bob_keypair)
            .unwrap();

    println!("  Sessions created for Alice and Bob");

    // === Message 1: Alice -> Bob ===
    let (ct1, h1) = alice_session
        .encrypt_message(b"Hello Bob! This is message 1.")
        .unwrap();
    println!("  Alice sent: \"Hello Bob! This is message 1.\"");

    let pt = bob_session.decrypt_message(&ct1, h1).unwrap();
    println!("  Bob received: \"{}\"", String::from_utf8_lossy(&pt));

    // === Message 2: Bob -> Alice (triggers DH ratchet) ===
    let (ct2, h2) = bob_session
        .encrypt_message(b"Hi Alice! Got your message.")
        .unwrap();
    println!("  Bob sent: \"Hi Alice! Got your message.\"");

    let pt = alice_session.decrypt_message(&ct2, h2).unwrap();
    println!("  Alice received: \"{}\"", String::from_utf8_lossy(&pt));

    // === Message 3: Alice -> Bob ===
    let (ct3, h3) = alice_session
        .encrypt_message(b"Great! Let's keep chatting.")
        .unwrap();
    println!("  Alice sent: \"Great! Let's keep chatting.\"");

    let pt = bob_session.decrypt_message(&ct3, h3).unwrap();
    println!("  Bob received: \"{}\"", String::from_utf8_lossy(&pt));

    // Print final state
    println!(
        "  State after conversation: Alice msg_send={}, Bob msg_recv={}",
        alice_session.msg_send(),
        bob_session.msg_recv()
    );
}

fn continue_after_restart(alice_storage: RatchetStorage, bob_storage: RatchetStorage, conv_id: &str) {
    // Load persisted states
    let mut alice_session: RatchetSession = RatchetSession::open(alice_storage, conv_id).unwrap();
    let mut bob_session: RatchetSession = RatchetSession::open(bob_storage, conv_id).unwrap();
    println!("  Sessions restored for Alice and Bob");

    // Continue conversation
    let (ct, header) = alice_session
        .encrypt_message(b"Message after restart!")
        .unwrap();
    println!("  Alice sent: \"Message after restart!\"");

    let pt = bob_session.decrypt_message(&ct, header).unwrap();
    println!("  Bob received: \"{}\"", String::from_utf8_lossy(&pt));

    println!(
        "  Final state: Alice msg_send={}, Bob msg_recv={}",
        alice_session.msg_send(),
        bob_session.msg_recv()
    );
}
