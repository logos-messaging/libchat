//! Chat application logic.

use std::path::PathBuf;

use anyhow::{Context, Result};
use logos_chat::{ChatManager, Introduction, StorageConfig};

use crate::transport::FileTransport;

/// A chat message for display.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DisplayMessage {
    pub from_self: bool,
    pub content: String,
    pub timestamp: u64,
}

/// The chat application state.
pub struct ChatApp {
    /// The logos-chat manager.
    pub manager: ChatManager,
    /// File-based transport for message passing.
    pub transport: FileTransport,
    /// Our introduction bundle (to share with others).
    pub intro_bundle: Option<Introduction>,
    /// Current chat ID (if in a conversation).
    pub current_chat_id: Option<String>,
    /// Remote user name (for transport).
    pub remote_user: Option<String>,
    /// Messages to display.
    pub messages: Vec<DisplayMessage>,
    /// Input buffer.
    pub input: String,
    /// Status message.
    pub status: String,
    /// Our user name.
    pub user_name: String,
}

impl ChatApp {
    /// Create a new chat application.
    pub fn new(user_name: &str, data_dir: &PathBuf, transport_dir: &PathBuf) -> Result<Self> {
        // Create database path
        let db_path = data_dir.join(format!("{}.db", user_name));
        std::fs::create_dir_all(data_dir)?;

        // Open or create the chat manager with file-based storage
        let manager = ChatManager::open(StorageConfig::File(
            db_path.to_string_lossy().to_string(),
        ))
        .context("Failed to open ChatManager")?;

        // Create file transport
        let transport = FileTransport::new(user_name, transport_dir)
            .context("Failed to create transport")?;

        Ok(Self {
            manager,
            transport,
            intro_bundle: None,
            current_chat_id: None,
            remote_user: None,
            messages: Vec::new(),
            input: String::new(),
            status: format!("Welcome, {}! Type /help for commands.", user_name),
            user_name: user_name.to_string(),
        })
    }

    /// Create and display our introduction bundle.
    pub fn create_intro(&mut self) -> Result<String> {
        let intro = self.manager.create_intro_bundle()?;
        let bundle_str: Vec<u8> = intro.clone().into();
        let bundle_string = String::from_utf8_lossy(&bundle_str).to_string();
        self.intro_bundle = Some(intro);
        self.status = "Introduction bundle created. Share it with others!".to_string();
        Ok(bundle_string)
    }

    /// Connect to another user using their introduction bundle.
    pub fn connect(&mut self, remote_user: &str, bundle_str: &str) -> Result<()> {
        let intro = Introduction::try_from(bundle_str.as_bytes())
            .map_err(|e| anyhow::anyhow!("Invalid bundle: {:?}", e))?;

        let (chat_id, envelopes) = self.manager.start_private_chat(&intro, "👋 Hello!")?;

        self.current_chat_id = Some(chat_id.clone());
        self.remote_user = Some(remote_user.to_string());

        // Send the envelopes via file transport
        for envelope in envelopes {
            self.transport.send(remote_user, envelope.data)?;
        }

        self.messages.push(DisplayMessage {
            from_self: true,
            content: "👋 Hello!".to_string(),
            timestamp: now(),
        });

        self.status = format!("Connected to {}! Chat ID: {}", remote_user, &chat_id[..8]);
        Ok(())
    }

    /// Send a message in the current chat.
    pub fn send_message(&mut self, content: &str) -> Result<()> {
        let chat_id = self.current_chat_id.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No active chat"))?;
        let remote_user = self.remote_user.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No remote user"))?;

        let envelopes = self.manager.send_message(chat_id, content.as_bytes())?;

        for envelope in envelopes {
            self.transport.send(remote_user, envelope.data)?;
        }

        self.messages.push(DisplayMessage {
            from_self: true,
            content: content.to_string(),
            timestamp: now(),
        });

        Ok(())
    }

    /// Process incoming messages from transport.
    pub fn process_incoming(&mut self) -> Result<()> {
        // Check for new messages
        while let Some(envelope) = self.transport.try_recv() {
            self.handle_incoming_envelope(&envelope)?;
        }
        Ok(())
    }

    /// Process existing messages on startup.
    pub fn process_existing(&mut self) -> Result<()> {
        let messages = self.transport.process_existing_messages();
        for envelope in messages {
            self.handle_incoming_envelope(&envelope)?;
        }
        Ok(())
    }

    /// Handle an incoming envelope.
    fn handle_incoming_envelope(&mut self, envelope: &crate::transport::FileEnvelope) -> Result<()> {
        match self.manager.handle_incoming(&envelope.data) {
            Ok(content) => {
                // Update chat state if this is a new chat
                if self.current_chat_id.is_none() {
                    self.current_chat_id = Some(content.conversation_id.clone());
                    self.remote_user = Some(envelope.from.clone());
                    self.status = format!("New chat from {}!", envelope.from);
                }

                let message = String::from_utf8_lossy(&content.data).to_string();
                if !message.is_empty() {
                    self.messages.push(DisplayMessage {
                        from_self: false,
                        content: message,
                        timestamp: envelope.timestamp,
                    });
                }
            }
            Err(e) => {
                self.status = format!("Error handling message: {}", e);
            }
        }
        Ok(())
    }

    /// Handle a command (starts with /).
    pub fn handle_command(&mut self, cmd: &str) -> Result<Option<String>> {
        let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
        let command = parts[0];
        let args = parts.get(1).copied().unwrap_or("");

        match command {
            "/help" => {
                Ok(Some(
                    "Commands:\n\
                     /intro - Show your introduction bundle\n\
                     /connect <user> <bundle> - Connect to a user\n\
                     /status - Show connection status\n\
                     /clear - Clear messages\n\
                     /quit - Exit".to_string()
                ))
            }
            "/intro" => {
                let bundle = self.create_intro()?;
                Ok(Some(format!("Your bundle:\n{}", bundle)))
            }
            "/connect" => {
                let connect_parts: Vec<&str> = args.splitn(2, ' ').collect();
                if connect_parts.len() < 2 {
                    return Ok(Some("Usage: /connect <username> <bundle>".to_string()));
                }
                let remote_user = connect_parts[0];
                let bundle = connect_parts[1];
                self.connect(remote_user, bundle)?;
                Ok(Some(format!("Connected to {}", remote_user)))
            }
            "/status" => {
                let status = match &self.current_chat_id {
                    Some(id) => format!(
                        "Chat ID: {}\nRemote: {}\nAddress: {}",
                        &id[..8.min(id.len())],
                        self.remote_user.as_deref().unwrap_or("none"),
                        self.manager.local_address()
                    ),
                    None => format!(
                        "No active chat\nAddress: {}",
                        self.manager.local_address()
                    ),
                };
                Ok(Some(status))
            }
            "/clear" => {
                self.messages.clear();
                Ok(Some("Messages cleared".to_string()))
            }
            "/quit" => {
                Ok(None) // Signal to quit
            }
            _ => Ok(Some(format!("Unknown command: {}", command))),
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
