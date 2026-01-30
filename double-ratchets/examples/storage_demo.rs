//! Demonstrates SQLite storage for Double Ratchet state persistence.
//!
//! Run with: cargo run --example storage_demo -p double-ratchets

use double_ratchets::{
    InstallationKeyPair, RatchetSession, SqliteRatchetStore, hkdf::PrivateV1Domain,
};

fn main() {
    println!("=== Double Ratchet Storage Demo ===\n");

    ensure_tmp_directory();
    let alice_db_path = "./tmp/double_ratchet_encrypted_alice.db";
    let bob_db_path = "./tmp/double_ratchet_encrypted_bob.db";
    let encryption_key = "super-secret-key-123!";
    let _ = std::fs::remove_file(alice_db_path);
    let _ = std::fs::remove_file(bob_db_path);

    // Initial conversation with encryption
    {
        let alice_storage = SqliteRatchetStore::new(alice_db_path, encryption_key)
            .expect("Failed to create alice encrypted storage");
        let bob_storage = SqliteRatchetStore::new(bob_db_path, encryption_key)
            .expect("Failed to create bob encrypted storage");
        println!(
            "  Encrypted database created at: {}, {}",
            alice_db_path, bob_db_path
        );
        run_conversation(alice_storage, bob_storage);
    }

    // Restart with correct key
    println!("\n  Simulating restart with encryption key...");
    {
        let alice_storage = SqliteRatchetStore::new(alice_db_path, encryption_key)
            .expect("Failed to create alice encrypted storage");
        let bob_storage = SqliteRatchetStore::new(bob_db_path, encryption_key)
            .expect("Failed to create bob encrypted storage");
        continue_after_restart(alice_storage, bob_storage);
    }

    let _ = std::fs::remove_file(alice_db_path);
    let _ = std::fs::remove_file(bob_db_path);
}

fn ensure_tmp_directory() {
    if let Err(e) = std::fs::create_dir_all("./tmp") {
        eprintln!("Failed to create tmp directory: {}", e);
        return;
    }
}

fn run_conversation(alice_storage: SqliteRatchetStore, bob_storage: SqliteRatchetStore) {
    let shared_secret = [0x42u8; 32];
    let bob_keypair = InstallationKeyPair::generate();
    let conv_id = "conv1";

    let mut alice_session: RatchetSession<SqliteRatchetStore, PrivateV1Domain> =
        RatchetSession::create_sender_session(
            alice_storage,
            conv_id,
            shared_secret,
            bob_keypair.public().clone(),
        )
        .unwrap();

    let mut bob_session: RatchetSession<SqliteRatchetStore, PrivateV1Domain> =
        RatchetSession::create_receiver_session(bob_storage, conv_id, shared_secret, bob_keypair)
            .unwrap();

    println!("  Sessions created for Alice and Bob");

    // Message 1: Alice -> Bob
    let (ct1, h1) = alice_session
        .encrypt_message(b"Hello Bob! This is message 1.")
        .unwrap();
    println!("  Alice sent: \"Hello Bob! This is message 1.\"");

    let pt = bob_session.decrypt_message(&ct1, h1).unwrap();
    println!("  Bob received: \"{}\"", String::from_utf8_lossy(&pt));

    // Message 2: Bob -> Alice
    let (ct2, h2) = bob_session
        .encrypt_message(b"Hi Alice! Got your message.")
        .unwrap();
    println!("  Bob sent: \"Hi Alice! Got your message.\"");

    let pt = alice_session.decrypt_message(&ct2, h2).unwrap();
    println!("  Alice received: \"{}\"", String::from_utf8_lossy(&pt));

    // Message 3: Alice -> Bob
    let (ct3, h3) = alice_session
        .encrypt_message(b"Great! Let's keep chatting.")
        .unwrap();
    println!("  Alice sent: \"Great! Let's keep chatting.\"");

    let pt = bob_session.decrypt_message(&ct3, h3).unwrap();
    println!("  Bob received: \"{}\"", String::from_utf8_lossy(&pt));

    println!(
        "  State after conversation: Alice msg_send={}, Bob msg_recv={}",
        alice_session.msg_send(),
        bob_session.msg_recv()
    );
}

fn continue_after_restart(alice_storage: SqliteRatchetStore, bob_storage: SqliteRatchetStore) {
    let conv_id = "conv1";

    let mut alice_session: RatchetSession<SqliteRatchetStore, PrivateV1Domain> =
        RatchetSession::open(alice_storage, conv_id).unwrap();
    let mut bob_session: RatchetSession<SqliteRatchetStore, PrivateV1Domain> =
        RatchetSession::open(bob_storage, conv_id).unwrap();
    println!("  Sessions restored for Alice and Bob");

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
