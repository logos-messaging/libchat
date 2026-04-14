//! Chat CLI - A terminal chat application using logos-chat.
//!
//! This application demonstrates how to use the logos-chat library
//! with file-based transport for local communication.
//!
//! # Usage
//!
//! Run two instances with different usernames:
//!
//! ```bash
//! # Terminal 1
//! cargo run -p chat-cli -- alice
//!
//! # Terminal 2  
//! cargo run -p chat-cli -- bob
//! ```
//!
//! Then in alice's terminal:
//! 1. Type `/intro` to get your introduction bundle
//! 2. Copy the bundle string
//!
//! In bob's terminal:
//! 1. Type `/connect alice <bundle>` (paste alice's bundle)
//!
//! Now bob can send messages to alice, and alice can reply.

mod app;
mod transport;
mod ui;

use std::path::PathBuf;

use anyhow::{Context, Result};

/// Get the data directory (in project folder).
fn get_data_dir() -> PathBuf {
    // Use the directory where the binary is or current working directory
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap_or(&PathBuf::from("."))
        .join("chat-cli-data")
}

fn main() -> Result<()> {
    // Parse arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <username>", args[0]);
        eprintln!("\nExample:");
        eprintln!("  Terminal 1: {} alice", args[0]);
        eprintln!("  Terminal 2: {} bob", args[0]);
        std::process::exit(1);
    }

    let user_name = &args[1];

    // Setup data directory in project folder
    let data_dir = get_data_dir();
    std::fs::create_dir_all(&data_dir).context("Failed to create data directory")?;

    println!("Starting chat as '{}'...", user_name);
    println!("Data dir: {:?}", data_dir);

    // Create app
    let mut app = app::ChatApp::new(user_name, &data_dir).context("Failed to create chat app")?;

    // Initialize terminal UI
    let mut terminal = ui::init().context("Failed to initialize terminal")?;

    // Main loop
    let result = run_app(&mut terminal, &mut app);

    // Restore terminal
    ui::restore().context("Failed to restore terminal")?;

    result
}

fn run_app(terminal: &mut ui::Tui, app: &mut app::ChatApp) -> Result<()> {
    loop {
        // Process incoming messages
        app.process_incoming()?;

        // Draw UI
        terminal.draw(|frame| ui::draw(frame, app))?;

        // Handle input
        if !ui::handle_events(app)? {
            break;
        }
    }

    Ok(())
}
