//! Example: Persistent Chat with SQLite Storage
//!
//! This example demonstrates how to persist and restore chat state using
//! SQLite storage, so users can restart the app and continue their chats.
//!
//! Run with: cargo run -p logos-chat --example persistent_chat

use logos_chat::{
    chat::ChatManager,
    identity::Identity,
    storage::{ChatStorage, ChatRecord},
};
use x25519_dalek::PublicKey;

fn main() {
    println!("=== Persistent Chat Example ===\n");

    // Use a temporary file for this example
    let db_path = "/tmp/chat_example.db";

    // Clean up from previous runs
    let _ = std::fs::remove_file(db_path);

    // =========================================
    // Part 1: First Session - Create and save state
    // =========================================
    println!("--- Part 1: First Session ---\n");

    {
        // Open storage
        let mut storage = ChatStorage::open(db_path)
            .expect("Failed to open storage");

        println!("1. Creating new identity...");
        let alice = ChatManager::new();
        let alice_address = alice.local_address();
        println!("   Address: {}...{}", &alice_address[..8], &alice_address[alice_address.len()-8..]);

        // Save identity to storage
        // Note: In a real app, you'd access the identity from ChatManager
        // For now, we'll create a separate identity to demonstrate storage
        let identity = Identity::new();
        storage.save_identity(&identity).expect("Failed to save identity");
        println!("   Identity saved to database");

        // Simulate creating some inbox keys
        println!("\n2. Creating inbox keys...");
        let secret1 = x25519_dalek::StaticSecret::random();
        let pub1 = PublicKey::from(&secret1);
        let pub1_hex = hex::encode(pub1.as_bytes());
        storage.save_inbox_key(&pub1_hex, &secret1).expect("Failed to save inbox key");
        println!("   Saved inbox key: {}...", &pub1_hex[..16]);

        let secret2 = x25519_dalek::StaticSecret::random();
        let pub2 = PublicKey::from(&secret2);
        let pub2_hex = hex::encode(pub2.as_bytes());
        storage.save_inbox_key(&pub2_hex, &secret2).expect("Failed to save inbox key");
        println!("   Saved inbox key: {}...", &pub2_hex[..16]);

        // Simulate creating some chats
        println!("\n3. Creating chat records...");
        let remote_key = PublicKey::from(&x25519_dalek::StaticSecret::random());
        let chat1 = ChatRecord::new_private(
            "chat_with_bob".to_string(),
            remote_key,
            "bob_delivery_addr".to_string(),
        );
        storage.save_chat(&chat1).expect("Failed to save chat");
        println!("   Saved chat: {}", chat1.chat_id);

        let remote_key2 = PublicKey::from(&x25519_dalek::StaticSecret::random());
        let chat2 = ChatRecord::new_private(
            "chat_with_carol".to_string(),
            remote_key2,
            "carol_delivery_addr".to_string(),
        );
        storage.save_chat(&chat2).expect("Failed to save chat");
        println!("   Saved chat: {}", chat2.chat_id);

        println!("\n   First session complete. Closing database...");
    }

    // =========================================
    // Part 2: Second Session - Restore state
    // =========================================
    println!("\n--- Part 2: Second Session (After Restart) ---\n");

    {
        // Reopen storage
        let storage = ChatStorage::open(db_path)
            .expect("Failed to open storage");

        println!("1. Restoring identity...");
        if let Some(identity) = storage.load_identity().expect("Failed to load identity") {
            let address = identity.address();
            println!("   Restored identity: {}...{}", &address[..8], &address[address.len()-8..]);
        } else {
            println!("   No identity found!");
        }

        println!("\n2. Restoring inbox keys...");
        let inbox_keys = storage.load_all_inbox_keys().expect("Failed to load inbox keys");
        println!("   Found {} inbox key(s)", inbox_keys.len());
        for (pub_hex, _secret) in &inbox_keys {
            println!("   - {}...", &pub_hex[..16]);
        }

        println!("\n3. Restoring chats...");
        let chats = storage.load_all_chats().expect("Failed to load chats");
        println!("   Found {} chat(s)", chats.len());
        for chat in &chats {
            println!("   - {} (type: {}, remote: {})",
                chat.chat_id,
                chat.chat_type,
                chat.remote_address
            );
        }

        // Demonstrate loading a specific chat
        println!("\n4. Loading specific chat...");
        if let Some(chat) = storage.load_chat("chat_with_bob").expect("Failed to load chat") {
            println!("   Chat ID: {}", chat.chat_id);
            println!("   Type: {}", chat.chat_type);
            println!("   Remote Address: {}", chat.remote_address);
            println!("   Created At: {}", chat.created_at);
        }

        // Demonstrate listing chat IDs
        println!("\n5. Listing all chat IDs...");
        let ids = storage.list_chat_ids().expect("Failed to list chat IDs");
        for id in ids {
            println!("   - {}", id);
        }
    }

    // Cleanup
    let _ = std::fs::remove_file(db_path);

    println!("\n=== Persistent Chat Example Complete ===");
    println!("\nNote: In a real application, you would:");
    println!("  1. Load identity on startup (or create new if none exists)");
    println!("  2. Restore inbox keys to handle incoming handshakes");
    println!("  3. Restore chat records and their associated ratchet states");
    println!("  4. Save state after each operation for durability");
}
