//! Example: Chat Flow with Automatic Persistence
//!
//! This example demonstrates the complete chat flow using ChatManager,
//! which automatically handles all storage operations.
//!
//! Run with: cargo run -p logos-chat --example persist_chat

use logos_chat::{ChatManager, StorageConfig};
use tempfile::TempDir;

fn main() {
    println!("=== Chat Flow Example ===\n");

    // Create temporary directories for databases
    let alice_dir = TempDir::new().expect("Failed to create temp dir");
    let bob_dir = TempDir::new().expect("Failed to create temp dir");

    let alice_db = alice_dir.path().join("alice.db");
    let bob_db = bob_dir.path().join("bob.db");

    // =========================================
    // Step 1: Create chat managers
    // =========================================
    println!("Step 1: Creating chat managers...\n");

    // In production, use StorageConfig::Encrypted { path, key }
    let mut alice = ChatManager::open(StorageConfig::File(alice_db.to_str().unwrap().to_string()))
        .expect("Failed to create Alice's chat manager");

    let mut bob = ChatManager::open(StorageConfig::File(bob_db.to_str().unwrap().to_string()))
        .expect("Failed to create Bob's chat manager");

    println!("  Alice's address: {}", alice.local_address());
    println!("  Bob's address: {}", bob.local_address());
    println!();

    // =========================================
    // Step 2: Bob creates intro bundle to share
    // =========================================
    println!("Step 2: Bob creates introduction bundle...\n");

    let bob_intro = bob
        .create_intro_bundle()
        .expect("Failed to create intro bundle");

    println!("  Bob shares his intro bundle with Alice");
    println!(
        "  (Installation key: {})",
        hex::encode(bob_intro.installation_key.as_bytes())
    );
    println!();

    // =========================================
    // Step 3: Alice starts a chat with Bob
    // =========================================
    println!("Step 3: Alice starts a private chat with Bob...\n");

    let (chat_id, envelopes) = alice
        .start_private_chat(&bob_intro, "Hello Bob! 👋")
        .expect("Failed to start chat");

    println!("  Chat created: {}", chat_id);
    println!("  Envelopes to deliver: {}", envelopes.len());
    println!("  (Chat automatically persisted to storage)");
    println!();

    // =========================================
    // Step 4: Alice sends more messages
    // =========================================
    println!("Step 4: Alice sends more messages...\n");

    let messages = ["How are you?", "Are you there?", "☕"];
    for msg in &messages {
        let envelopes = alice
            .send_message(&chat_id, msg.as_bytes())
            .expect("Failed to send message");
        println!("  → \"{}\" ({} envelope)", msg, envelopes.len());
    }
    println!();

    // =========================================
    // Step 5: Verify persistence
    // =========================================
    println!("Step 5: Verifying persistence...\n");

    println!(
        "  Chats persisted to storage: {:?}",
        alice.list_chats().unwrap()
    );
    println!();

    // =========================================
    // Step 6: Simulate app restart
    // =========================================
    println!("Step 6: Simulating app restart...\n");

    let alice_address = alice.local_address();
    drop(alice); // Close Alice's chat manager

    println!("  Chat manager closed. Reopening...\n");

    let alice_restored =
        ChatManager::open(StorageConfig::File(alice_db.to_str().unwrap().to_string()))
            .expect("Failed to reopen Alice's chat manager");

    println!("  ✓ Chat manager restored!");
    println!(
        "  ✓ Same address: {}",
        alice_restored.local_address() == alice_address
    );
    println!(
        "  ✓ Stored chats: {:?}",
        alice_restored.list_chats().unwrap()
    );
    println!();

    // =========================================
    // Done!
    // =========================================
    println!("=== Example Complete ===\n");
    println!("Key points:");
    println!("  • ChatManager handles all storage internally");
    println!("  • Identity is automatically created and persisted");
    println!("  • Chats are automatically saved when created");
    println!("  • State survives app restarts");
    println!();
    println!("For production, use encrypted storage:");
    println!("  ChatManager::open(StorageConfig::Encrypted {{");
    println!("      path: \"chat.db\".into(),");
    println!("      key: \"user_encryption_key\".into(),");
    println!("  }})");

    // Temp directories are automatically cleaned up
}
