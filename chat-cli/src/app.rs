//! Chat application logic.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use logos_chat::{ChatManager, Introduction, StorageConfig};
use serde::{Deserialize, Serialize};

use crate::transport::FileTransport;

/// A chat message for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayMessage {
    pub from_self: bool,
    pub content: String,
    pub timestamp: u64,
}

/// Metadata for a chat session (persisted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatSession {
    pub chat_id: String,
    pub remote_user: String,
    pub messages: Vec<DisplayMessage>,
}

/// App state that gets persisted.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AppState {
    /// Map from remote username to chat session.
    pub sessions: HashMap<String, ChatSession>,
    /// Currently active chat (remote username).
    pub active_chat: Option<String>,
}

/// The chat application state.
pub struct ChatApp {
    /// The logos-chat manager.
    pub manager: ChatManager,
    /// File-based transport for message passing.
    pub transport: FileTransport,
    /// Our introduction bundle (to share with others).
    pub intro_bundle: Option<Introduction>,
    /// Persisted app state.
    pub state: AppState,
    /// Global messages (shown when no active chat).
    pub global_messages: Vec<DisplayMessage>,
    /// Input buffer.
    pub input: String,
    /// Status message.
    pub status: String,
    /// Our user name.
    pub user_name: String,
    /// Path to state file.
    state_path: PathBuf,
    /// Data directory.
    data_dir: PathBuf,
}

impl ChatApp {
    /// Create a new chat application.
    pub fn new(user_name: &str, data_dir: &PathBuf) -> Result<Self> {
        // Create database path
        let db_path = data_dir.join(format!("{}.db", user_name));
        std::fs::create_dir_all(data_dir)?;

        // Open or create the chat manager with file-based storage
        let manager = ChatManager::open(StorageConfig::File(db_path.to_string_lossy().to_string()))
            .context("Failed to open ChatManager")?;

        // Create file-based transport
        let transport =
            FileTransport::new(user_name, data_dir).context("Failed to create file transport")?;

        // Load persisted state
        let state_path = data_dir.join(format!("{}_state.json", user_name));
        let state = Self::load_state(&state_path);

        // Count existing chats
        let chat_count = state.sessions.len();
        let status = if chat_count > 0 {
            format!(
                "Welcome back, {}! {} chat(s) loaded. Type /help for commands.",
                user_name, chat_count
            )
        } else {
            format!("Welcome, {}! Type /help for commands.", user_name)
        };

        Ok(Self {
            manager,
            transport,
            intro_bundle: None,
            state,
            global_messages: Vec::new(),
            input: String::new(),
            status,
            user_name: user_name.to_string(),
            state_path,
            data_dir: data_dir.clone(),
        })
    }

    /// Load state from file.
    fn load_state(path: &PathBuf) -> AppState {
        if path.exists() {
            if let Ok(contents) = fs::read_to_string(path) {
                if let Ok(state) = serde_json::from_str(&contents) {
                    return state;
                }
            }
        }
        AppState::default()
    }

    /// Save state to file.
    fn save_state(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.state)?;
        fs::write(&self.state_path, json)?;
        Ok(())
    }

    /// Get the current chat session (if any).
    pub fn current_session(&self) -> Option<&ChatSession> {
        self.state
            .active_chat
            .as_ref()
            .and_then(|name| self.state.sessions.get(name))
    }

    /// Get the current messages to display.
    pub fn messages(&self) -> Vec<&DisplayMessage> {
        if let Some(session) = self.current_session() {
            session.messages.iter().collect()
        } else {
            // Show global messages when no active chat
            self.global_messages.iter().collect()
        }
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
        // Check if we already have a chat with this user
        if self.state.sessions.contains_key(remote_user) {
            return Err(anyhow::anyhow!(
                "Already have a chat with {}. Use /switch {} to switch to it.",
                remote_user,
                remote_user
            ));
        }

        let intro = Introduction::try_from(bundle_str.as_bytes())
            .map_err(|e| anyhow::anyhow!("Invalid bundle: {:?}", e))?;

        let (chat_id, envelopes) = self.manager.start_private_chat(&intro, "👋 Hello!")?;

        // Send the envelopes via file transport
        for envelope in envelopes {
            self.transport.send(remote_user, envelope.data)?;
        }

        // Create new session
        let mut session = ChatSession {
            chat_id: chat_id.clone(),
            remote_user: remote_user.to_string(),
            messages: Vec::new(),
        };
        session.messages.push(DisplayMessage {
            from_self: true,
            content: "👋 Hello!".to_string(),
            timestamp: now(),
        });

        self.state.sessions.insert(remote_user.to_string(), session);
        self.state.active_chat = Some(remote_user.to_string());
        self.save_state()?;

        self.status = format!("Connected to {}!", remote_user);
        Ok(())
    }

    /// Switch to a different chat.
    pub fn switch_chat(&mut self, remote_user: &str) -> Result<()> {
        if self.state.sessions.contains_key(remote_user) {
            self.state.active_chat = Some(remote_user.to_string());
            self.save_state()?;
            self.status = format!("Switched to chat with {}", remote_user);
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "No chat with {}. Use /chats to list available chats.",
                remote_user
            ))
        }
    }

    /// Delete a chat session.
    pub fn delete_chat(&mut self, remote_user: &str) -> Result<()> {
        if let Some(session) = self.state.sessions.remove(remote_user) {
            // Also delete from the library's storage
            if let Err(e) = self.manager.delete_chat(&session.chat_id) {
                // Log but don't fail - the CLI state is already updated
                self.status = format!("Warning: failed to delete crypto state: {}", e);
            }

            // If we deleted the active chat, clear it
            if self.state.active_chat.as_deref() == Some(remote_user) {
                // Switch to another chat if available, otherwise clear
                self.state.active_chat = self.state.sessions.keys().next().cloned();
            }

            self.save_state()?;
            self.status = format!("Deleted chat with {}", remote_user);
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "No chat with {}. Use /chats to list available chats.",
                remote_user
            ))
        }
    }

    /// Send a message in the current chat.
    pub fn send_message(&mut self, content: &str) -> Result<()> {
        let active = self
            .state
            .active_chat
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No active chat. Use /connect or /switch first."))?;

        let session = self
            .state
            .sessions
            .get(&active)
            .ok_or_else(|| anyhow::anyhow!("Chat session not found"))?;

        let chat_id = session.chat_id.clone();
        let remote_user = session.remote_user.clone();

        let envelopes = self.manager.send_message(&chat_id, content.as_bytes())?;

        for envelope in envelopes {
            self.transport.send(&remote_user, envelope.data)?;
        }

        // Update messages
        if let Some(session) = self.state.sessions.get_mut(&active) {
            session.messages.push(DisplayMessage {
                from_self: true,
                content: content.to_string(),
                timestamp: now(),
            });
        }
        self.save_state()?;

        Ok(())
    }

    /// Process incoming messages from transport.
    pub fn process_incoming(&mut self) -> Result<()> {
        while let Some(envelope) = self.transport.try_recv() {
            self.handle_incoming_envelope(&envelope)?;
        }
        Ok(())
    }

    /// Handle an incoming envelope.
    fn handle_incoming_envelope(
        &mut self,
        envelope: &crate::transport::MessageEnvelope,
    ) -> Result<()> {
        match self.manager.handle_incoming(&envelope.data) {
            Ok(content) => {
                let from_user = &envelope.from;
                let chat_id = content.conversation_id.clone();

                // Find or create session for this user
                if !self.state.sessions.contains_key(from_user) {
                    // New chat from someone
                    let session = ChatSession {
                        chat_id: chat_id.clone(),
                        remote_user: from_user.clone(),
                        messages: Vec::new(),
                    };
                    self.state.sessions.insert(from_user.clone(), session);
                    self.state.active_chat = Some(from_user.clone());
                    self.status = format!("New chat from {}!", from_user);
                }

                let message = String::from_utf8_lossy(&content.data).to_string();
                if !message.is_empty() {
                    if let Some(session) = self.state.sessions.get_mut(from_user) {
                        session.messages.push(DisplayMessage {
                            from_self: false,
                            content: message,
                            timestamp: envelope.timestamp,
                        });
                    }
                }

                self.save_state()?;
            }
            Err(e) => {
                self.status = format!("Error: {}", e);
            }
        }
        Ok(())
    }

    /// Add a system message to the current chat (for display only).
    fn add_system_message(&mut self, content: &str) {
        let msg = DisplayMessage {
            from_self: true,
            content: content.to_string(),
            timestamp: now(),
        };

        if let Some(active) = &self.state.active_chat.clone() {
            if let Some(session) = self.state.sessions.get_mut(active) {
                session.messages.push(msg);
                return;
            }
        }
        // No active chat - add to global messages
        self.global_messages.push(msg);
    }

    /// Handle a command (starts with /).
    pub fn handle_command(&mut self, cmd: &str) -> Result<Option<String>> {
        let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
        let command = parts[0];
        let args = parts.get(1).copied().unwrap_or("");

        match command {
            "/help" => {
                self.add_system_message("── Commands ──");
                self.add_system_message("/intro - Show your introduction bundle");
                self.add_system_message("/connect <user> <bundle> - Connect to a user");
                self.add_system_message("/chats - List all chats");
                self.add_system_message("/switch <user> - Switch to chat with user");
                self.add_system_message("/delete <user> - Delete chat with user");
                self.add_system_message("/peers - List transport peers");
                self.add_system_message("/status - Show connection status");
                self.add_system_message("/clear - Clear current chat messages");
                self.add_system_message("/quit or Esc or Ctrl+C - Exit");
                Ok(Some("Help displayed".to_string()))
            }
            "/intro" => {
                let bundle = self.create_intro()?;
                self.add_system_message("── Your Introduction Bundle ──");
                self.add_system_message(&bundle);
                self.add_system_message("Share this bundle with others to connect!");
                Ok(Some("Bundle created".to_string()))
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
            "/chats" => {
                let sessions: Vec<_> = self.state.sessions.keys().cloned().collect();
                if sessions.is_empty() {
                    Ok(Some("No chats yet. Use /connect to start one.".to_string()))
                } else {
                    self.add_system_message(&format!("── Your Chats ({}) ──", sessions.len()));
                    for name in &sessions {
                        let marker = if Some(name) == self.state.active_chat.as_ref() {
                            " (active)"
                        } else {
                            ""
                        };
                        self.add_system_message(&format!("  • {}{}", name, marker));
                    }
                    Ok(Some(format!("{} chat(s)", sessions.len())))
                }
            }
            "/switch" => {
                if args.is_empty() {
                    return Ok(Some("Usage: /switch <username>".to_string()));
                }
                self.switch_chat(args)?;
                Ok(Some(format!("Switched to {}", args)))
            }
            "/delete" => {
                if args.is_empty() {
                    return Ok(Some("Usage: /delete <username>".to_string()));
                }
                self.delete_chat(args)?;
                Ok(Some(format!("Deleted chat with {}", args)))
            }
            "/peers" => {
                let peers = self.transport.list_peers();
                if peers.is_empty() {
                    Ok(Some(
                        "No peers found. Start another chat-cli instance.".to_string(),
                    ))
                } else {
                    self.add_system_message(&format!("── Peers ({}) ──", peers.len()));
                    for peer in &peers {
                        self.add_system_message(&format!("  • {}", peer));
                    }
                    Ok(Some(format!("{} peer(s)", peers.len())))
                }
            }
            "/status" => {
                let chats = self.state.sessions.len();
                let active = self.state.active_chat.as_deref().unwrap_or("none");
                let status = format!(
                    "User: {}\nAddress: {}\nChats: {}\nActive: {}",
                    self.user_name,
                    self.manager.local_address(),
                    chats,
                    active
                );
                Ok(Some(status))
            }
            "/clear" => {
                if let Some(active) = &self.state.active_chat {
                    if let Some(session) = self.state.sessions.get_mut(active) {
                        session.messages.clear();
                        self.save_state()?;
                    }
                }
                Ok(Some("Messages cleared".to_string()))
            }
            "/quit" => Ok(None),
            _ => Ok(Some(format!(
                "Unknown command: {}. Type /help for commands.",
                command
            ))),
        }
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
