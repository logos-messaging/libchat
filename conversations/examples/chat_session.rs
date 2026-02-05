//! Example: Chat Session with Automatic Persistence
//!
//! This example demonstrates using ChatSession which automatically
//! persists all state changes to SQLite storage.
//!
//! Run with: cargo run -p logos-chat --example chat_session

use logos_chat::storage::ChatSession;
use tempfile::TempDir;

fn main() {
    println!("=== Chat Session Example ===\n");

    // Create temporary directories for databases
    let alice_dir = TempDir::new().expect("Failed to create temp dir");
    let bob_dir = TempDir::new().expect("Failed to create temp dir");

    let alice_db = alice_dir.path().join("alice.db");
    let bob_db = bob_dir.path().join("bob.db");

    // =========================================
    // Create sessions for Alice and Bob
    // =========================================
    println!("Step 1: Creating chat sessions...\n");

    let mut alice = ChatSession::open_or_create(alice_db.to_str().unwrap(), "alice_secret_key")
        .expect("Failed to create Alice's session");
    println!("  Alice's session created");
    println!("  Address: {}", &alice.local_address());

    let mut bob = ChatSession::open_or_create(bob_db.to_str().unwrap(), "bob_secret_key")
        .expect("Failed to create Bob's session");
    println!("  Bob's session created");
    println!("  Address: {}", &bob.local_address());
    println!();

    // =========================================
    // Bob creates intro bundle
    // =========================================
    println!("Step 2: Bob creates introduction bundle...\n");
    let bob_intro = bob
        .create_intro_bundle()
        .expect("Failed to create intro bundle");
    println!("  Bob's intro bundle created");
    println!(
        "  Installation key: {}",
        &hex::encode(bob_intro.installation_key.as_bytes())
    );
    println!();

    // =========================================
    // Alice starts a chat with Bob
    // =========================================
    println!("Step 3: Alice starts a private chat with Bob...\n");
    let (chat_id, envelopes) = alice
        .start_private_chat(&bob_intro, "Hello Bob! 👋")
        .expect("Failed to start chat");

    println!("  Chat created: {}", chat_id);
    println!("  Envelopes to deliver: {}", envelopes.len());
    println!("  Chat automatically saved to storage!");
    println!();

    // =========================================
    // Verify persistence by checking storage
    // =========================================
    println!("Step 4: Verifying persistence...\n");

    // Check Alice's storage directly
    let chat_record = alice
        .storage()
        .load_chat(&chat_id)
        .expect("Failed to load chat");

    if let Some(record) = chat_record {
        println!("  Chat record found in storage:");
        println!("    - ID: {}", record.chat_id);
        println!("    - Type: {}", record.chat_type);
        println!("    - Remote: {}", record.remote_address);
    }
    println!();

    // =========================================
    // Alice sends more messages
    // =========================================
    println!("Step 5: Alice sends more messages...\n");

    let messages = [
        "How are you?",
        "Are you there?",
        "Let me know when you're free!",
    ];
    for msg in &messages {
        let envelopes = alice
            .send_message(&chat_id, msg.as_bytes())
            .expect("Failed to send message");
        println!("  Sent: \"{}\" ({} envelope(s))", msg, envelopes.len());
    }
    println!();

    // =========================================
    // Simulate app restart - reopen session
    // =========================================
    println!("Step 6: Simulating app restart...\n");
    drop(alice); // Close Alice's session

    println!("  Session closed. Reopening...\n");

    let alice_restored = ChatSession::open(alice_db.to_str().unwrap(), "alice_secret_key")
        .expect("Failed to reopen Alice's session");

    println!("  Session restored!");
    println!("  Address: {}", &alice_restored.local_address());

    // Note: The chats list will be empty because we haven't implemented
    // full chat restoration yet (which requires restoring ratchet states)
    println!("  Chats in memory: {}", alice_restored.list_chats().len());

    // But the chat metadata is persisted in storage
    let stored_chats = alice_restored
        .storage()
        .list_chat_ids()
        .expect("Failed to list chats");
    println!("  Chats in storage: {:?}", stored_chats);
    println!();

    println!("=== Chat Session Example Complete ===\n");
    println!("Key features demonstrated:");
    println!("  ✓ Automatic identity persistence");
    println!("  ✓ Automatic chat metadata persistence");
    println!("  ✓ Session recovery after restart");
    println!();
    println!("TODO:");
    println!("  - Full inbox key persistence");
    println!("  - Ratchet state persistence (integration with double-ratchets storage)");
    println!("  - Complete chat restoration on session open");

    // Temp directories are automatically cleaned up when dropped
}
