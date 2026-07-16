use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use arboard::Clipboard;
use crossbeam_channel::Receiver;
use logos_chat::{AccountDirectory, ChatClient, ChatStore, Event, RegistrationService, Transport};
use serde::{Deserialize, Serialize};

use crate::utils::now;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayMessage {
    pub from_self: bool,
    pub content: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatSession {
    pub chat_id: String,
    pub nickname: Option<String>,
    pub messages: Vec<DisplayMessage>,
}

impl ChatSession {
    /// Human-readable label: nickname if set, otherwise the first 8 chars of the chat ID.
    pub fn display_name(&self) -> &str {
        self.nickname
            .as_deref()
            .unwrap_or_else(|| &self.chat_id[..8.min(self.chat_id.len())])
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AppState {
    /// Keyed by chat_id (conversation ID).
    pub chats: HashMap<String, ChatSession>,
    /// Holds the active chat_id.
    pub active_chat: Option<String>,
}

pub struct ChatApp<T, R, S>
where
    T: Transport,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    S: ChatStore + Send + 'static,
{
    pub client: ChatClient<T, R, S>,
    events: Receiver<Event>,
    pub state: AppState,
    /// Ephemeral command output — not persisted, cleared on chat switch.
    command_output: Vec<DisplayMessage>,
    pub input: String,
    pub status: String,
    pub user_name: String,
    state_path: PathBuf,
}

impl<T, R, S> ChatApp<T, R, S>
where
    T: Transport,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
    S: ChatStore + Send,
{
    pub fn new(
        client: ChatClient<T, R, S>,
        events: Receiver<Event>,
        user_name: &str,
        data_dir: &Path,
    ) -> Result<Self> {
        fs::create_dir_all(data_dir)?;

        let state_path = data_dir.join(format!("{user_name}_state.json"));
        let state = Self::load_state(&state_path);

        let chat_count = state.chats.len();
        let status = if chat_count > 0 {
            format!(
                "Welcome back, {user_name}! {chat_count} chat(s) loaded. Type /help for commands."
            )
        } else {
            format!("Welcome, {user_name}! Type /help for commands.")
        };

        Ok(Self {
            client,
            events,
            state,
            command_output: Vec::new(),
            input: String::new(),
            status,
            user_name: user_name.to_string(),
            state_path,
        })
    }

    fn load_state(path: &Path) -> AppState {
        if path.exists()
            && let Ok(contents) = fs::read_to_string(path)
            && let Ok(state) = serde_json::from_str(&contents)
        {
            return state;
        }
        AppState::default()
    }

    fn save_state(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.state)?;
        fs::write(&self.state_path, json)?;
        Ok(())
    }

    pub fn current_session(&self) -> Option<&ChatSession> {
        self.state
            .active_chat
            .as_ref()
            .and_then(|name| self.state.chats.get(name))
    }

    pub fn messages(&self) -> Vec<&DisplayMessage> {
        let chat = self
            .current_session()
            .map(|s| s.messages.as_slice())
            .unwrap_or(&[]);
        chat.iter().chain(self.command_output.iter()).collect()
    }

    fn set_active_chat(&mut self, chat_id: Option<String>) {
        self.state.active_chat = chat_id;
        self.command_output.clear();
    }

    /// Find a chat_id by nickname (exact) or chat_id prefix.
    fn resolve_chat_id(&self, query: &str) -> Option<&str> {
        // Exact nickname match first.
        if let Some((id, _)) = self
            .state
            .chats
            .iter()
            .find(|(_, s)| s.nickname.as_deref() == Some(query))
        {
            return Some(id.as_str());
        }
        // Fall back to chat_id prefix.
        self.state
            .chats
            .keys()
            .find(|id| id.starts_with(query))
            .map(String::as_str)
    }

    pub fn process_incoming(&mut self) -> Result<()> {
        let mut received = false;
        while let Ok(event) = self.events.try_recv() {
            self.handle_event(event);
            received = true;
        }
        if received {
            self.save_state()?;
        }
        Ok(())
    }

    fn handle_event(&mut self, event: Event) {
        match event {
            Event::ConversationStarted { convo_id, .. } => {
                let chat_id = convo_id.to_string();
                if self.state.chats.contains_key(&chat_id) {
                    return;
                }
                self.state.chats.insert(
                    chat_id.clone(),
                    ChatSession {
                        chat_id: chat_id.clone(),
                        nickname: None,
                        messages: Vec::new(),
                    },
                );
                let label = &chat_id[..8.min(chat_id.len())];
                self.status = format!("New chat ({label})! Use /nickname to name it.");
                self.set_active_chat(Some(chat_id));
            }
            Event::MessageReceived {
                convo_id, content, ..
            } => {
                let chat_id = convo_id.to_string();
                let Some(session) = self.state.chats.get_mut(&chat_id) else {
                    return;
                };
                session.messages.push(DisplayMessage {
                    from_self: false,
                    content: String::from_utf8_lossy(&content).into_owned(),
                    timestamp: now(),
                });
            }
            Event::InboundError { message } => {
                self.status = format!("Could not process incoming message: {message}");
            }
            _ => {}
        }
    }

    pub fn send_message(&mut self, content: &str) -> Result<()> {
        let chat_id = self
            .state
            .active_chat
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No active chat. Use /connect or /switch first."))?;

        self.client
            .send_message(&chat_id, content.as_bytes())
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;

        if let Some(session) = self.state.chats.get_mut(&chat_id) {
            session.messages.push(DisplayMessage {
                from_self: true,
                content: content.to_string(),
                timestamp: now(),
            });
        }
        self.save_state()?;

        Ok(())
    }

    fn add_system_message(&mut self, content: &str) {
        self.command_output.push(DisplayMessage {
            from_self: true,
            content: content.to_string(),
            timestamp: now(),
        });
    }

    pub fn handle_command(&mut self, cmd: &str) -> Result<Option<String>> {
        let parts: Vec<&str> = cmd.splitn(2, ' ').collect();
        let command = parts[0];
        let args = parts.get(1).copied().unwrap_or("");

        match command {
            "/help" => {
                self.add_system_message("── Commands ──");
                self.add_system_message("/intro - Show your address");
                self.add_system_message("/connect <address> - Connect using an address");
                self.add_system_message("/nickname <name> - Name the active chat");
                self.add_system_message("/chats - List all chats");
                self.add_system_message("/switch <name|id> - Switch active chat");
                self.add_system_message("/delete <name|id> - Delete a chat");
                self.add_system_message("/status - Show connection status");
                self.add_system_message("/clear - Clear current chat messages");
                self.add_system_message("/quit or Esc or Ctrl+C - Exit");
                Ok(Some("Help displayed".to_string()))
            }
            "/intro" => {
                let address = self.client.addr().to_string();
                self.add_system_message("── Your Address ──");
                self.add_system_message(&address);
                let clipboard_msg = match Clipboard::new().and_then(|mut cb| cb.set_text(&address))
                {
                    Ok(()) => "Address copied to clipboard! Share it, then /connect their address.",
                    Err(_) => "Share this address with others to connect!",
                };
                self.add_system_message(clipboard_msg);
                Ok(Some("Address shown".to_string()))
            }
            "/connect" => {
                if args.is_empty() {
                    return Ok(Some("Usage: /connect <address>".to_string()));
                }
                let initial = format!("Hello from {}!", self.user_name);
                let chat_id = self
                    .client
                    .create_direct_conversation(args)
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
                self.client
                    .send_message(&chat_id, initial.as_bytes())
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?;

                let label = chat_id[..8.min(chat_id.len())].to_string();
                let mut session = ChatSession {
                    chat_id: chat_id.clone(),
                    nickname: None,
                    messages: Vec::new(),
                };
                session.messages.push(DisplayMessage {
                    from_self: true,
                    content: initial,
                    timestamp: now(),
                });
                self.state.chats.insert(chat_id.clone(), session);
                self.set_active_chat(Some(chat_id));
                self.save_state()?;
                self.status = format!("Connected ({label})! Use /nickname to name this chat.");
                Ok(Some(format!("Connected ({label})")))
            }
            "/nickname" => {
                if args.is_empty() {
                    return Ok(Some("Usage: /nickname <name>".to_string()));
                }
                let chat_id = self
                    .state
                    .active_chat
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("No active chat."))?;
                let session = self
                    .state
                    .chats
                    .get_mut(&chat_id)
                    .ok_or_else(|| anyhow::anyhow!("Chat session not found."))?;
                session.nickname = Some(args.to_string());
                self.save_state()?;
                self.status = format!("Chat named '{args}'.");
                Ok(Some(format!("Nickname set to '{args}'")))
            }
            "/chats" => {
                let sessions: Vec<_> = self.state.chats.values().cloned().collect();
                if sessions.is_empty() {
                    Ok(Some("No chats yet. Use /connect to start one.".to_string()))
                } else {
                    self.add_system_message(&format!("── Your Chats ({}) ──", sessions.len()));
                    for s in &sessions {
                        let marker = if self.state.active_chat.as_deref() == Some(&s.chat_id) {
                            " (active)"
                        } else {
                            ""
                        };
                        let label = format!(
                            "  • {} ({}){marker}",
                            s.display_name(),
                            &s.chat_id[..8.min(s.chat_id.len())]
                        );
                        self.add_system_message(&label);
                    }
                    Ok(Some(format!("{} chat(s)", sessions.len())))
                }
            }
            "/switch" => {
                if args.is_empty() {
                    return Ok(Some("Usage: /switch <nickname|id-prefix>".to_string()));
                }
                let chat_id = self
                    .resolve_chat_id(args)
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("No chat matching '{args}'."))?;
                let label = self.state.chats[&chat_id].display_name().to_string();
                self.set_active_chat(Some(chat_id));
                self.save_state()?;
                self.status = format!("Switched to '{label}'.");
                Ok(Some(format!("Switched to '{label}'")))
            }
            "/delete" => {
                if args.is_empty() {
                    return Ok(Some("Usage: /delete <nickname|id-prefix>".to_string()));
                }
                let chat_id = self
                    .resolve_chat_id(args)
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("No chat matching '{args}'."))?;
                let label = self.state.chats[&chat_id].display_name().to_string();
                self.state.chats.remove(&chat_id);
                if self.state.active_chat.as_deref() == Some(&chat_id) {
                    self.state.active_chat = self.state.chats.keys().next().cloned();
                }
                self.save_state()?;
                self.status = format!("Deleted '{label}'.");
                Ok(Some(format!("Deleted '{label}'")))
            }
            "/status" => {
                let active_label = self
                    .state
                    .active_chat
                    .as_ref()
                    .and_then(|id| self.state.chats.get(id))
                    .map(|s| {
                        format!(
                            "{} ({})",
                            s.display_name(),
                            &s.chat_id[..8.min(s.chat_id.len())]
                        )
                    })
                    .unwrap_or_else(|| "none".to_string());
                let status = format!(
                    "User: {}\nIdentity: {}\nChats: {}\nActive: {}",
                    self.user_name,
                    self.client.installation_name(),
                    self.state.chats.len(),
                    active_label,
                );
                Ok(Some(status))
            }
            "/clear" => {
                if let Some(active) = &self.state.active_chat.clone()
                    && let Some(session) = self.state.chats.get_mut(active)
                {
                    session.messages.clear();
                    self.save_state()?;
                }
                Ok(Some("Messages cleared".to_string()))
            }
            "/quit" => Ok(None),
            _ => Ok(Some(format!(
                "Unknown command: {command}. Type /help for commands."
            ))),
        }
    }
}
