//! Example: Ping-Pong Chat
//!
//! This example demonstrates a back-and-forth conversation between two users.
//! Note: The handle_incoming implementation is currently stubbed, so this
//! demonstrates the API flow rather than full encryption roundtrip.
//!
//! Run with: cargo run -p logos-chat --example ping_pong

use logos_chat::chat::ChatManager;

fn main() {
    println!("=== Ping-Pong Chat Example ===\n");

    // Create two chat participants
    let mut alice = ChatManager::new();
    let mut bob = ChatManager::new();

    println!("Created participants:");
    println!("  Alice: {}", &alice.local_address());
    println!("  Bob:   {}", &bob.local_address());
    println!();

    // Bob shares his intro bundle with Alice
    let bob_intro = bob.create_intro_bundle().unwrap();
    println!("Bob shared his introduction bundle with Alice\n");

    // Alice initiates the conversation
    let (alice_chat_id, initial_envelopes) = alice.start_private_chat(&bob_intro, "Ping!").unwrap();

    println!("Alice -> Bob: \"Ping!\"");
    println!("  Chat ID: {}", &alice_chat_id);
    println!("  Envelopes: {}", initial_envelopes.len());

    // Simulate delivering to Bob (stub)
    for env in &initial_envelopes {
        let _ = bob.handle_incoming(&env.data);
    }
    println!();

    // Continue the conversation
    let messages = [("Alice", "How's it going?"), ("Alice", "Are you there?")];

    for (sender, msg) in &messages {
        let envelopes = alice.send_message(&alice_chat_id, msg.as_bytes()).unwrap();

        println!("{} -> Bob: \"{}\"", sender, msg);
        println!("  Envelopes: {}", envelopes.len());

        // Simulate delivery
        for env in &envelopes {
            let _ = bob.handle_incoming(&env.data);
        }
    }

    println!();
    println!("Chat statistics:");
    println!("  Alice's active chats: {}", alice.list_chats().len());
    println!("  Bob's active chats: {}", bob.list_chats().len());
    println!();

    println!("=== Example Complete ===");
    println!();
    println!("Note: Full message roundtrip requires implementing handle_incoming()");
    println!("to properly decrypt messages and establish the chat on the receiver side.");
}
