//! Example: Ping-Pong Chat
//!
//! This example demonstrates a back-and-forth conversation between two users
//! using temporary file storage.
//!
//! Run with: cargo run -p logos-chat --example ping_pong

use logos_chat::{ChatManager, StorageConfig};
use tempfile::tempdir;

fn main() {
    println!("=== Ping-Pong Chat Example ===\n");

    // Create temporary directories for storage
    let dir = tempdir().expect("Failed to create temp dir");
    let alice_db = dir.path().join("alice.db");
    let bob_db = dir.path().join("bob.db");

    // Create two chat participants with file-based storage
    let mut alice = ChatManager::open(StorageConfig::File(alice_db.to_str().unwrap().to_string()))
        .expect("Failed to create Alice's chat manager");
    let mut bob = ChatManager::open(StorageConfig::File(bob_db.to_str().unwrap().to_string()))
        .expect("Failed to create Bob's chat manager");

    println!("Created participants:");
    println!("  Alice: {}", alice.local_address());
    println!("  Bob:   {}", bob.local_address());
    println!();

    // Bob shares his intro bundle with Alice
    let bob_intro = bob.create_intro_bundle().unwrap();
    println!("Bob shared his introduction bundle with Alice\n");

    // Alice initiates the conversation
    let (alice_chat_id, initial_envelopes) = alice.start_private_chat(&bob_intro, "Ping!").unwrap();

    println!("Alice -> Bob: \"Ping!\"");
    println!("  Chat ID: {}", &alice_chat_id);
    println!("  Envelopes: {}", initial_envelopes.len());

    // Bob receives the message
    let envelope = initial_envelopes.first().unwrap();
    let content = bob.handle_incoming(&envelope.data).unwrap();
    println!(
        "  Bob received: \"{}\"",
        String::from_utf8_lossy(&content.data)
    );

    // Get Bob's chat ID (same as Alice's due to shared conversation_hint)
    let bob_chat_id = bob.list_chats().unwrap().first().unwrap().clone();
    println!("  Bob's chat ID: {}", &bob_chat_id);
    println!();

    // Bob replies
    let bob_envelopes = bob.send_message(&bob_chat_id, b"Pong!").unwrap();
    println!("Bob -> Alice: \"Pong!\"");
    println!("  Envelopes: {}", bob_envelopes.len());

    let bob_reply = bob_envelopes.first().unwrap();
    let alice_received = alice.handle_incoming(&bob_reply.data).unwrap();
    println!(
        "  Alice received: \"{}\"",
        String::from_utf8_lossy(&alice_received.data)
    );
    println!();

    // Continue the conversation
    let alice_messages = ["How's it going?", "Are you there?"];
    let bob_replies = ["Pretty good!", "Yes, I'm here!"];

    for (msg, reply) in alice_messages.iter().zip(bob_replies.iter()) {
        // Alice sends
        let envelopes = alice.send_message(&alice_chat_id, msg.as_bytes()).unwrap();
        println!("Alice -> Bob: \"{}\"", msg);

        let env = envelopes.first().unwrap();
        let bob_received = bob.handle_incoming(&env.data).unwrap();
        println!(
            "  Bob received: \"{}\"",
            String::from_utf8_lossy(&bob_received.data)
        );

        // Bob replies
        let bob_envs = bob.send_message(&bob_chat_id, reply.as_bytes()).unwrap();
        println!("Bob -> Alice: \"{}\"", reply);

        let bob_env = bob_envs.first().unwrap();
        let alice_got = alice.handle_incoming(&bob_env.data).unwrap();
        println!(
            "  Alice received: \"{}\"",
            String::from_utf8_lossy(&alice_got.data)
        );
        println!();
    }

    println!("Chat statistics:");
    println!("  Alice's chats: {:?}", alice.list_chats().unwrap());
    println!("  Bob's chats: {:?}", bob.list_chats().unwrap());
    println!();

    println!("=== Example Complete ===");
}
