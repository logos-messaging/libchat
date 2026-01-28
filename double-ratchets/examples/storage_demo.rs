//! Demonstrates SQLite storage for Double Ratchet state persistence.
//!
//! Run with: cargo run --example storage_demo --features persist

#[cfg(feature = "persist")]
use double_ratchets::{
    InstallationKeyPair, RatchetSession, RatchetStorage, StorageConfig, hkdf::PrivateV1Domain,
};

fn main() {
    println!("=== Double Ratchet Storage Demo ===\n");

    // Demo 1: In-memory storage (for testing)
    println!("--- Demo 1: In-Memory Storage ---");
    #[cfg(feature = "persist")]
    demo_in_memory();
    #[cfg(not(feature = "persist"))]
    println!("  (skipped - enable 'persist' feature)");

    // Demo 2: File-based storage (for local development)
    println!("\n--- Demo 2: File-Based Storage ---");
    #[cfg(feature = "persist")]
    demo_file_storage();
    #[cfg(not(feature = "persist"))]
    println!("  (skipped - enable 'persist' feature)");

    // Demo 3: SQLCipher encrypted storage (for production)
    println!("\n--- Demo 3: SQLCipher Encrypted Storage ---");
    #[cfg(feature = "persist")]
    demo_sqlcipher();
    #[cfg(not(feature = "persist"))]
    println!("  (skipped - enable 'persist' feature)");
}

#[cfg(feature = "persist")]
fn demo_in_memory() {
    let mut alice_storage =
        RatchetStorage::with_config(StorageConfig::InMemory).expect("Failed to create storage");
    let mut bob_storage =
        RatchetStorage::with_config(StorageConfig::InMemory).expect("Failed to create storage");
    run_conversation(&mut alice_storage, &mut bob_storage);
}

#[cfg(feature = "persist")]
fn demo_file_storage() {
    ensure_tmp_directory();

    let db_path_alice = "./tmp/double_ratchet_demo_alice.db";
    let db_path_bob = "./tmp/double_ratchet_demo_bob.db";
    let _ = std::fs::remove_file(db_path_alice);
    let _ = std::fs::remove_file(db_path_bob);

    // Initial conversation
    {
        let mut alice_storage = RatchetStorage::with_config(StorageConfig::File(db_path_alice.to_string()))
            .expect("Failed to create storage");

        let mut bob_storage = RatchetStorage::with_config(StorageConfig::File(db_path_bob.to_string()))
            .expect("Failed to create storage");

        println!("  Database created at: {}, {}", db_path_alice, db_path_bob);
        run_conversation(&mut alice_storage, &mut bob_storage);
    }

    // Simulate restart - reopen and continue
    println!("\n  Simulating application restart...");
    {
        let mut alice_storage = RatchetStorage::with_config(StorageConfig::File(db_path_alice.to_string()))
            .expect("Failed to reopen storage");
        let mut bob_storage = RatchetStorage::with_config(StorageConfig::File(db_path_bob.to_string()))
            .expect("Failed to reopen storage");
        continue_after_restart(&mut alice_storage, &mut bob_storage);
    }

    let _ = std::fs::remove_file(db_path_alice);
    let _ = std::fs::remove_file(db_path_bob);
}

#[cfg(feature = "persist")]
fn demo_sqlcipher() {
    ensure_tmp_directory();
    let alice_db_path = "./tmp/double_ratchet_encrypted_alice.db";
    let bob_db_path = "./tmp/double_ratchet_encrypted_bob.db";
    let encryption_key = "super-secret-key-123!";
    let _ = std::fs::remove_file(alice_db_path);
    let _ = std::fs::remove_file(bob_db_path);

    // Initial conversation with encryption
    {
        let mut alice_storage = RatchetStorage::with_config(StorageConfig::Encrypted {
            path: alice_db_path.to_string(),
            key: encryption_key.to_string(),
        })
        .expect("Failed to create encrypted storage");
        let mut bob_storage = RatchetStorage::with_config(StorageConfig::Encrypted {
            path: bob_db_path.to_string(),
            key: encryption_key.to_string(),
        })
        .expect("Failed to create encrypted storage");
        println!(
            "  Encrypted database created at: {}, {}",
            alice_db_path, bob_db_path
        );
        run_conversation(&mut alice_storage, &mut bob_storage);
    }

    // Restart with correct key
    println!("\n  Simulating restart with encryption key...");
    {
        let mut alice_storage = RatchetStorage::with_config(StorageConfig::Encrypted {
            path: alice_db_path.to_string(),
            key: encryption_key.to_string(),
        })
        .expect("Failed to create encrypted storage");
        let mut bob_storage = RatchetStorage::with_config(StorageConfig::Encrypted {
            path: bob_db_path.to_string(),
            key: encryption_key.to_string(),
        })
        .expect("Failed to create encrypted storage");
        continue_after_restart(&mut alice_storage, &mut bob_storage);
    }

    let _ = std::fs::remove_file(alice_db_path);
    let _ = std::fs::remove_file(bob_db_path);
}

#[allow(dead_code)]
fn ensure_tmp_directory() {
    if let Err(e) = std::fs::create_dir_all("./tmp") {
        eprintln!("Failed to create tmp directory: {}", e);
        return; // Or handle as needed
    }
}

/// Simulates a conversation between Alice and Bob.
/// Each party saves/loads state from storage for each operation.
#[cfg(feature = "persist")]
fn run_conversation(alice_storage: &mut RatchetStorage, bob_storage: &mut RatchetStorage) {
    // === Setup: Simulate X3DH key exchange ===
    let shared_secret = [0x42u8; 32]; // In reality, this comes from X3DH
    let bob_keypair = InstallationKeyPair::generate();

    let conv_id = "conv1";

    let mut alice_session: RatchetSession<PrivateV1Domain> = RatchetSession::create_sender_session(
        alice_storage,
        conv_id,
        shared_secret,
        bob_keypair.public().clone(),
    )
    .unwrap();

    let mut bob_session: RatchetSession<PrivateV1Domain> =
        RatchetSession::create_receiver_session(bob_storage, conv_id, shared_secret, bob_keypair)
            .unwrap();

    println!("  Sessions created for Alice and Bob");

    // === Message 1: Alice -> Bob ===
    let (ct1, h1) = {
        let result = alice_session
            .encrypt_message(b"Hello Bob! This is message 1.")
            .unwrap();
        println!("  Alice sent: \"Hello Bob! This is message 1.\"");
        result
    };

    {
        let pt = bob_session.decrypt_message(&ct1, h1).unwrap();
        println!("  Bob received: \"{}\"", String::from_utf8_lossy(&pt));
    }

    // === Message 2: Bob -> Alice (triggers DH ratchet) ===
    let (ct2, h2) = {
        let result = bob_session
            .encrypt_message(b"Hi Alice! Got your message.")
            .unwrap();
        println!("  Bob sent: \"Hi Alice! Got your message.\"");
        result
    };

    {
        let pt = alice_session.decrypt_message(&ct2, h2).unwrap();
        println!("  Alice received: \"{}\"", String::from_utf8_lossy(&pt));
    }

    // === Message 3: Alice -> Bob ===
    let (ct3, h3) = {
        let result = alice_session
            .encrypt_message(b"Great! Let's keep chatting.")
            .unwrap();
        println!("  Alice sent: \"Great! Let's keep chatting.\"");
        result
    };

    {
        let pt = bob_session.decrypt_message(&ct3, h3).unwrap();
        println!("  Bob received: \"{}\"", String::from_utf8_lossy(&pt));
    }

    // Print final state
    println!(
        "  State after conversation: Alice msg_send={}, Bob msg_recv={}",
        alice_session.msg_send(),
        bob_session.msg_recv()
    );
}

#[cfg(feature = "persist")]
fn continue_after_restart(alice_storage: &mut RatchetStorage, bob_storage: &mut RatchetStorage) {
    // Load persisted states
    let conv_id = "conv1";

    let mut alice_session: RatchetSession<PrivateV1Domain> =
        RatchetSession::open(alice_storage, conv_id).unwrap();
    let mut bob_session: RatchetSession<PrivateV1Domain> =
        RatchetSession::open(bob_storage, conv_id).unwrap();
    println!("  Sessions restored for Alice and Bob",);

    // Continue conversation
    let (ct, header) = {
        let result = alice_session
            .encrypt_message(b"Message after restart!")
            .unwrap();
        println!("  Alice sent: \"Message after restart!\"");
        result
    };

    {
        let pt = bob_session.decrypt_message(&ct, header).unwrap();
        println!("  Bob received: \"{}\"", String::from_utf8_lossy(&pt));
    }

    println!(
        "  Final state: Alice msg_send={}, Bob msg_recv={}",
        alice_session.msg_send(),
        bob_session.msg_recv()
    );
}
