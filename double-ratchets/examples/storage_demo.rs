//! Demonstrates SQLite storage for Double Ratchet state persistence.
//!
//! Run with: cargo run --example storage_demo --features storage
//! For SQLCipher: cargo run --example storage_demo --features sqlcipher

use double_ratchets::{
    InstallationKeyPair, RatchetState, SqliteStorage, StorageConfig, hkdf::DefaultDomain,
};

fn main() {
    println!("=== Double Ratchet Storage Demo ===\n");

    // Demo 1: In-memory storage (for testing)
    println!("--- Demo 1: In-Memory Storage ---");
    demo_in_memory();

    // Demo 2: File-based storage (for local development)
    println!("\n--- Demo 2: File-Based Storage ---");
    demo_file_storage();

    // Demo 3: SQLCipher encrypted storage (for production)
    #[cfg(feature = "sqlcipher")]
    {
        println!("\n--- Demo 3: SQLCipher Encrypted Storage ---");
        demo_sqlcipher();
    }

    #[cfg(not(feature = "sqlcipher"))]
    {
        println!("\n--- Demo 3: SQLCipher (skipped - enable 'sqlcipher' feature) ---");
    }
}

fn demo_in_memory() {
    let mut storage =
        SqliteStorage::new(StorageConfig::InMemory).expect("Failed to create storage");
    run_conversation(&mut storage);
}

fn demo_file_storage() {
    ensure_tmp_directory();

    let db_path = "./tmp/double_ratchet_demo.db";
    let _ = std::fs::remove_file(db_path);

    // Initial conversation
    {
        let mut storage = SqliteStorage::new(StorageConfig::File(db_path.to_string()))
            .expect("Failed to create storage");
        println!("  Database created at: {}", db_path);
        run_conversation(&mut storage);
    }

    // Simulate restart - reopen and continue
    println!("\n  Simulating application restart...");
    {
        let mut storage = SqliteStorage::new(StorageConfig::File(db_path.to_string()))
            .expect("Failed to reopen storage");
        continue_after_restart(&mut storage);
    }

    let _ = std::fs::remove_file(db_path);
}

#[cfg(feature = "sqlcipher")]
fn demo_sqlcipher() {
    ensure_tmp_directory();
    let db_path = "./tmp/double_ratchet_encrypted.db";
    let encryption_key = "super-secret-key-123!";
    let _ = std::fs::remove_file(db_path);

    // Initial conversation with encryption
    {
        let mut storage = SqliteStorage::new(StorageConfig::Encrypted {
            path: db_path.to_string(),
            key: encryption_key.to_string(),
        })
        .expect("Failed to create encrypted storage");
        println!("  Encrypted database created at: {}", db_path);
        run_conversation(&mut storage);
    }

    // Restart with correct key
    println!("\n  Simulating restart with encryption key...");
    {
        let mut storage = SqliteStorage::new(StorageConfig::Encrypted {
            path: db_path.to_string(),
            key: encryption_key.to_string(),
        })
        .expect("Failed to reopen encrypted storage");
        continue_after_restart(&mut storage);
    }

    let _ = std::fs::remove_file(db_path);
}

fn ensure_tmp_directory() {
    if let Err(e) = std::fs::create_dir_all("./tmp") {
        eprintln!("Failed to create tmp directory: {}", e);
        return; // Or handle as needed
    }
}

/// Simulates a conversation between Alice and Bob.
/// Each party saves/loads state from storage for each operation.
fn run_conversation(storage: &mut SqliteStorage) {
    // === Setup: Simulate X3DH key exchange ===
    let shared_secret = [0x42u8; 32]; // In reality, this comes from X3DH
    let bob_keypair = InstallationKeyPair::generate();

    // Initialize and save both states
    let alice_state: RatchetState<DefaultDomain> =
        RatchetState::init_sender(shared_secret, bob_keypair.public().clone());
    let bob_state: RatchetState<DefaultDomain> =
        RatchetState::init_receiver(shared_secret, bob_keypair);

    storage.save("alice", &alice_state).expect("Save failed");
    storage.save("bob", &bob_state).expect("Save failed");
    println!("  Sessions created for Alice and Bob");

    // === Message 1: Alice -> Bob ===
    let (ct1, h1) = {
        let mut alice: RatchetState<DefaultDomain> = storage.load("alice").unwrap();
        let result = alice.encrypt_message(b"Hello Bob! This is message 1.");
        storage.save("alice", &alice).unwrap();
        result
    };
    println!("  Alice sent: \"Hello Bob! This is message 1.\"");

    {
        let mut bob: RatchetState<DefaultDomain> = storage.load("bob").unwrap();
        let pt = bob.decrypt_message(&ct1, h1).unwrap();
        storage.save("bob", &bob).unwrap();
        println!("  Bob received: \"{}\"", String::from_utf8_lossy(&pt));
    }

    // === Message 2: Bob -> Alice (triggers DH ratchet) ===
    let (ct2, h2) = {
        let mut bob: RatchetState<DefaultDomain> = storage.load("bob").unwrap();
        let result = bob.encrypt_message(b"Hi Alice! Got your message.");
        storage.save("bob", &bob).unwrap();
        result
    };
    println!("  Bob sent: \"Hi Alice! Got your message.\"");

    {
        let mut alice: RatchetState<DefaultDomain> = storage.load("alice").unwrap();
        let pt = alice.decrypt_message(&ct2, h2).unwrap();
        storage.save("alice", &alice).unwrap();
        println!("  Alice received: \"{}\"", String::from_utf8_lossy(&pt));
    }

    // === Message 3: Alice -> Bob ===
    let (ct3, h3) = {
        let mut alice: RatchetState<DefaultDomain> = storage.load("alice").unwrap();
        let result = alice.encrypt_message(b"Great! Let's keep chatting.");
        storage.save("alice", &alice).unwrap();
        result
    };
    println!("  Alice sent: \"Great! Let's keep chatting.\"");

    {
        let mut bob: RatchetState<DefaultDomain> = storage.load("bob").unwrap();
        let pt = bob.decrypt_message(&ct3, h3).unwrap();
        storage.save("bob", &bob).unwrap();
        println!("  Bob received: \"{}\"", String::from_utf8_lossy(&pt));
    }

    // Print final state
    let alice: RatchetState<DefaultDomain> = storage.load("alice").unwrap();
    let bob: RatchetState<DefaultDomain> = storage.load("bob").unwrap();
    println!(
        "  State after conversation: Alice msg_send={}, Bob msg_recv={}",
        alice.msg_send, bob.msg_recv
    );
}

fn continue_after_restart(storage: &mut SqliteStorage) {
    // Load persisted states
    let alice: RatchetState<DefaultDomain> = storage.load("alice").unwrap();
    let bob: RatchetState<DefaultDomain> = storage.load("bob").unwrap();
    println!(
        "  Sessions restored: Alice msg_send={}, Bob msg_recv={}",
        alice.msg_send, bob.msg_recv
    );

    // Continue conversation
    let (ct, header) = {
        let mut alice: RatchetState<DefaultDomain> = storage.load("alice").unwrap();
        let result = alice.encrypt_message(b"Message after restart!");
        storage.save("alice", &alice).unwrap();
        result
    };
    println!("  Alice sent: \"Message after restart!\"");

    {
        let mut bob: RatchetState<DefaultDomain> = storage.load("bob").unwrap();
        let pt = bob.decrypt_message(&ct, header).unwrap();
        storage.save("bob", &bob).unwrap();
        println!("  Bob received: \"{}\"", String::from_utf8_lossy(&pt));
    }

    let alice: RatchetState<DefaultDomain> = storage.load("alice").unwrap();
    let bob: RatchetState<DefaultDomain> = storage.load("bob").unwrap();
    println!(
        "  Final state: Alice msg_send={}, Bob msg_recv={}",
        alice.msg_send, bob.msg_recv
    );
}
