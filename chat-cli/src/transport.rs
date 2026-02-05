//! File-based transport for local chat communication.
//!
//! Messages are passed between users via files in a shared directory.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// A message envelope for transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    pub from: String,
    pub data: Vec<u8>,
    pub timestamp: u64,
}

/// File-based transport for local communication.
pub struct FileTransport {
    /// Our user name.
    user_name: String,
    /// Base directory for transport files.
    base_dir: PathBuf,
    /// Our inbox directory.
    inbox_dir: PathBuf,
    /// Set of processed message files (to avoid reprocessing).
    processed: HashSet<String>,
}

impl FileTransport {
    /// Create a new file transport.
    pub fn new(user_name: &str, data_dir: &PathBuf) -> Result<Self> {
        let base_dir = data_dir.join("transport");
        let inbox_dir = base_dir.join(user_name);
        
        // Create our inbox directory
        fs::create_dir_all(&inbox_dir)
            .context("Failed to create inbox directory")?;

        Ok(Self {
            user_name: user_name.to_string(),
            base_dir,
            inbox_dir,
            processed: HashSet::new(),
        })
    }

    /// Send a message to a specific user.
    pub fn send(&self, to_user: &str, data: Vec<u8>) -> Result<()> {
        let target_dir = self.base_dir.join(to_user);
        
        // Create target inbox if it doesn't exist
        fs::create_dir_all(&target_dir)
            .context("Failed to create target inbox")?;

        let envelope = MessageEnvelope {
            from: self.user_name.clone(),
            data,
            timestamp: now(),
        };

        // Write message to a unique file
        let filename = format!("{}_{}.json", self.user_name, now());
        let filepath = target_dir.join(&filename);
        
        let json = serde_json::to_string_pretty(&envelope)?;
        fs::write(&filepath, json)
            .context("Failed to write message file")?;

        Ok(())
    }

    /// Try to receive an incoming message (non-blocking).
    pub fn try_recv(&mut self) -> Option<MessageEnvelope> {
        // List files in our inbox
        let entries = match fs::read_dir(&self.inbox_dir) {
            Ok(e) => e,
            Err(_) => return None,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            
            // Skip non-json files
            if path.extension().map(|e| e != "json").unwrap_or(true) {
                continue;
            }

            let filename = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();

            // Skip already processed files
            if self.processed.contains(&filename) {
                continue;
            }

            // Try to read and parse the message
            if let Ok(contents) = fs::read_to_string(&path) {
                if let Ok(envelope) = serde_json::from_str::<MessageEnvelope>(&contents) {
                    // Mark as processed and delete
                    self.processed.insert(filename);
                    let _ = fs::remove_file(&path);
                    return Some(envelope);
                }
            }
        }

        None
    }

    /// List available peers (users with inbox directories).
    pub fn list_peers(&self) -> Vec<String> {
        let mut peers = Vec::new();
        
        if let Ok(entries) = fs::read_dir(&self.base_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        if name != self.user_name {
                            peers.push(name.to_string());
                        }
                    }
                }
            }
        }
        
        peers
    }

    /// Get our user name.
    #[allow(dead_code)]
    pub fn user_name(&self) -> &str {
        &self.user_name
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
