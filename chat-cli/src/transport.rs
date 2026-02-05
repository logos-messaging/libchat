//! File-based transport for local chat simulation.
//!
//! Each user has an inbox directory where other users drop messages.
//! Messages are JSON files with envelope data.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher, Event, EventKind};
use serde::{Deserialize, Serialize};

/// A message envelope for file-based transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEnvelope {
    pub from: String,
    pub data: Vec<u8>,
    pub timestamp: u64,
}

/// File-based transport for simulating message passing.
pub struct FileTransport {
    /// Our user name (used for inbox directory).
    user_name: String,
    /// Base directory for all inboxes.
    base_dir: PathBuf,
    /// Channel for receiving incoming messages.
    incoming_rx: Receiver<FileEnvelope>,
    /// Watcher handle (kept alive).
    _watcher: RecommendedWatcher,
}

impl FileTransport {
    /// Create a new file transport.
    ///
    /// `user_name` is used to create an inbox directory.
    /// `base_dir` is the shared directory where all user inboxes live.
    pub fn new(user_name: &str, base_dir: &Path) -> Result<Self> {
        let inbox_dir = base_dir.join(user_name);
        fs::create_dir_all(&inbox_dir)
            .with_context(|| format!("Failed to create inbox dir: {:?}", inbox_dir))?;

        let (tx, rx) = mpsc::channel();
        let watcher = Self::start_watcher(&inbox_dir, tx)?;

        Ok(Self {
            user_name: user_name.to_string(),
            base_dir: base_dir.to_path_buf(),
            incoming_rx: rx,
            _watcher: watcher,
        })
    }

    /// Start watching the inbox directory for new messages.
    fn start_watcher(inbox_dir: &Path, tx: Sender<FileEnvelope>) -> Result<RecommendedWatcher> {
        let mut watcher = RecommendedWatcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    if matches!(event.kind, EventKind::Create(_)) {
                        for path in event.paths {
                            if path.extension().map(|e| e == "json").unwrap_or(false) {
                                // Small delay to ensure file is fully written
                                thread::sleep(Duration::from_millis(50));
                                if let Ok(envelope) = Self::read_message(&path) {
                                    let _ = tx.send(envelope);
                                    // Delete the message after reading
                                    let _ = fs::remove_file(&path);
                                }
                            }
                        }
                    }
                }
            },
            Config::default().with_poll_interval(Duration::from_millis(100)),
        )?;

        watcher.watch(inbox_dir, RecursiveMode::NonRecursive)?;
        Ok(watcher)
    }

    /// Read a message from a file.
    fn read_message(path: &Path) -> Result<FileEnvelope> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let envelope: FileEnvelope = serde_json::from_str(&contents)?;
        Ok(envelope)
    }

    /// Send a message to another user's inbox.
    pub fn send(&self, to_user: &str, data: Vec<u8>) -> Result<()> {
        let to_inbox = self.base_dir.join(to_user);
        fs::create_dir_all(&to_inbox)?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let envelope = FileEnvelope {
            from: self.user_name.clone(),
            data,
            timestamp,
        };

        let filename = format!("{}_{}.json", self.user_name, timestamp);
        let path = to_inbox.join(filename);

        let json = serde_json::to_string_pretty(&envelope)?;
        let mut file = File::create(&path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;

        Ok(())
    }

    /// Try to receive an incoming message (non-blocking).
    pub fn try_recv(&self) -> Option<FileEnvelope> {
        self.incoming_rx.try_recv().ok()
    }

    /// Get our user name.
    #[allow(dead_code)]
    pub fn user_name(&self) -> &str {
        &self.user_name
    }

    /// Process any existing messages in inbox on startup.
    pub fn process_existing_messages(&self) -> Vec<FileEnvelope> {
        let inbox_dir = self.base_dir.join(&self.user_name);
        let mut messages = Vec::new();

        if let Ok(entries) = fs::read_dir(&inbox_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Ok(envelope) = Self::read_message(&path) {
                        messages.push(envelope);
                        let _ = fs::remove_file(&path);
                    }
                }
            }
        }

        // Sort by timestamp
        messages.sort_by_key(|m| m.timestamp);
        messages
    }
}
