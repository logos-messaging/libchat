//! A room chat over logos-delivery's reliable channels.
//!
//! Every participant runs one process, joins a channel named after the room and
//! types into it. There is no encryption of the chat itself and no libchat
//! stack here — the point is the channels API on its own.
//!
//! ```sh
//! cargo run -p channel-chat -- --nick Alice --room lobby
//! cargo run -p channel-chat -- --nick Bob   --room lobby
//! ```
//!
//! ## What channels buy
//!
//! Sending is `channel_send` rather than a relay publish, so the node runs SDS
//! underneath: acknowledgement, retransmission of unacknowledged messages, and
//! causal ordering. The cost is that delivery is no longer fire-and-forget, so
//! this example subscribes to the outcome events (`sent` / `error`) and shows
//! them in the status bar — without that, a failed send is silent.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};
use serde::{Deserialize, Serialize};
use waku_bindings::LogosDeliveryCtx;

/// What actually travels on the channel.
///
/// The nick rides inside the payload rather than being read off the event's
/// `sender_id`: logos-delivery fills that field in from the *receiving*
/// channel's own participant id (`reliable_channel.nim`'s `reportReceived`
/// emits `self.senderId`), so every inbound message would otherwise be
/// attributed to whoever is reading it.
#[derive(Serialize, Deserialize)]
struct ChatLine {
    nick: String,
    text: String,
}

/// The network to join. It also settles sharding: a channel's shard is derived
/// from its content topic, so the node needs autosharding, and this preset
/// supplies it (cluster 2, 8 shards) along with the entry nodes that let two
/// participants find each other.
const NETWORK_PRESET: &str = "logos.dev";
const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const DIAL_TIMEOUT_MS: u32 = 10_000;
const NOOP_ENCRYPTION: &str = "noop";
/// Poll cadence for the input loop; also caps how long quitting takes.
const INPUT_POLL: Duration = Duration::from_millis(200);

#[derive(Parser, Debug)]
#[command(
    name = "channel-chat",
    about = "Room chat over logos-delivery reliable channels"
)]
struct Cli {
    /// Your display name. Doubles as the channel's SDS participant id.
    #[arg(long, short)]
    nick: String,

    /// The room to join. Everyone in a room shares one channel.
    #[arg(long, short, default_value = "lobby")]
    room: String,

    /// TCP port for the node. `0` lets the OS pick a free one.
    #[arg(long, default_value_t = 0)]
    port: usize,

    /// Multiaddr of a peer to dial directly. The preset's entry nodes normally
    /// bring participants together on their own; this is for wiring two local
    /// instances up without waiting on discovery (each prints its address at
    /// startup).
    #[arg(long)]
    peer: Option<String>,
}

fn content_topic_for(room: &str) -> String {
    format!("/logos-chat-example/1/{room}/proto")
}

/// Lines shown in the chat pane, shared with the node's event callbacks.
type Log = Arc<Mutex<Vec<String>>>;

struct App {
    input: String,
    nick: String,
    room: String,
    channel_id: String,
    content_topic: String,
    messages: Log,
    /// The last channel outcome (`sent` / `error`) the node reported.
    status: Arc<Mutex<String>>,
    peer: Option<String>,
    node: LogosDeliveryCtx,
}

impl App {
    async fn new(cli: &Cli) -> Result<Self> {
        // Per-nick, and this is load-bearing: the persistency layer is a
        // process-wide singleton keyed on this path, and SDS rows are keyed by
        // channel id. Two participants sharing a path would each load the
        // other's causal history and silently drop their messages as replays.
        let storage_path = format!("./data-channel-chat-{}", cli.nick);

        // Hand-rolled rather than the typed `WakuNodeConfig`, which has no
        // `preset`/`mode` field — and the preset is what brings the entry nodes
        // and autosharding a channel needs. `discv5UdpPort` tracks the TCP port
        // so a second instance on one machine collides on neither.
        let config = serde_json::json!({
            "logLevel": "FATAL", // anything louder corrupts the TUI
            "mode": "Core",
            "preset": NETWORK_PRESET,
            "tcpPort": cli.port,
            "discv5UdpPort": cli.port,
            "local-storage-path": storage_path,
        })
        .to_string();

        let node = LogosDeliveryCtx::new_async(config, NODE_TIMEOUT)
            .await
            .map_err(anyhow::Error::msg)
            .context("failed to create the node")?;

        Ok(Self {
            input: String::new(),
            nick: cli.nick.clone(),
            room: cli.room.clone(),
            channel_id: cli.room.clone(),
            content_topic: content_topic_for(&cli.room),
            messages: Arc::new(Mutex::new(Vec::new())),
            status: Arc::new(Mutex::new("starting...".into())),
            peer: cli.peer.clone(),
            node,
        })
    }

    /// Register the listeners, start the node, then open and subscribe the room
    /// channel.
    async fn start(&self) -> Result<()> {
        let messages = self.messages.clone();
        // Registered before the node starts, so nothing can arrive unobserved.
        self.node
            .add_on_channel_message_received_listener(move |event| {
                let line = BASE64
                    .decode(&event.payload)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<ChatLine>(&bytes).ok());
                let rendered = match line {
                    Some(line) => format!("[{}]: {}", line.nick, line.text),
                    None => "<undecodable message>".to_string(),
                };
                messages.lock().unwrap().push(rendered);
            });

        // The two events that make a reliable send observable.
        let status = self.status.clone();
        self.node
            .add_on_channel_message_sent_listener(move |event| {
                *status.lock().unwrap() = format!("sent (request {})", event.request_id);
            });

        let status = self.status.clone();
        self.node
            .add_on_channel_message_error_listener(move |event| {
                *status.lock().unwrap() = format!("SEND FAILED: {}", event.error);
            });

        self.node
            .start_node_async()
            .await
            .map_err(anyhow::Error::msg)
            .context("failed to start the node")?;

        // Printed before the TUI takes the screen, so another instance can be
        // pointed at this one with --peer.
        if let Ok(addresses) = self.node.waku_listen_addresses_async().await {
            println!("Listening on: {addresses}");
        }

        if let Some(peer) = &self.peer {
            self.node
                .waku_connect_async(peer.clone(), DIAL_TIMEOUT_MS)
                .await
                .map_err(anyhow::Error::msg)
                .context("failed to dial the peer")?;
        }

        self.node
            .channel_create_async(
                self.channel_id.clone(),
                self.content_topic.clone(),
                // The participant id. Distinct per peer, or SDS treats two
                // peers as one and drops the second's messages as replays.
                self.nick.clone(),
                NOOP_ENCRYPTION.to_string(),
            )
            .await
            .map_err(anyhow::Error::msg)
            .context("failed to create the channel")?;

        // Creating a channel does not subscribe to its content topic: ingress
        // arrives through the messaging layer, so without this nothing lands.
        self.node
            .subscribe_async(self.content_topic.clone())
            .await
            .map_err(anyhow::Error::msg)
            .context("failed to subscribe to the channel topic")?;

        *self.status.lock().unwrap() = format!("joined #{}", self.room);
        Ok(())
    }

    async fn send(&self, text: String) {
        let line = ChatLine {
            nick: self.nick.clone(),
            text: text.clone(),
        };
        let encoded = match serde_json::to_vec(&line) {
            Ok(bytes) => bytes,
            Err(e) => {
                *self.status.lock().unwrap() = format!("SEND FAILED: {e}");
                return;
            }
        };

        let req = waku_bindings::ChannelSendRequest {
            payload: BASE64.encode(&encoded),
            ephemeral: false,
        };

        match self
            .node
            .channel_send_async(self.channel_id.clone(), req)
            .await
        {
            // Echoed locally: a node does not receive its own channel messages.
            Ok(_) => self
                .messages
                .lock()
                .unwrap()
                .push(format!("[{}]: {}", self.nick, text)),
            Err(e) => *self.status.lock().unwrap() = format!("SEND FAILED: {e}"),
        }
    }

    async fn stop(self) {
        let _ = self.node.channel_close_async(self.channel_id.clone()).await;
        let _ = self.node.stop_node_async().await;
        // The node itself is torn down by LogosDeliveryCtx's Drop impl.
    }
}

async fn run<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| ui(f, &*app))?;

        // Non-blocking so the draw above keeps picking up messages that arrive
        // on the node's callback threads while no key is pressed.
        if !event::poll(INPUT_POLL)? {
            continue;
        }

        let Event::Key(key) = event::read()? else {
            continue;
        };
        // Windows reports press and release; without this every key doubles.
        if key.kind != KeyEventKind::Press {
            continue;
        }

        match key.code {
            KeyCode::Esc => return Ok(()),
            KeyCode::Enter => {
                let text = app.input.trim().to_string();
                if !text.is_empty() {
                    app.send(text).await;
                    app.input.clear();
                }
            }
            KeyCode::Char(c) => app.input.push(c),
            KeyCode::Backspace => {
                app.input.pop();
            }
            _ => {}
        }
    }
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1), // status
            Constraint::Min(1),    // messages
            Constraint::Length(3), // input
        ])
        .split(f.area());

    let status = app.status.lock().unwrap().clone();
    let failed = status.starts_with("SEND FAILED");
    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" #{} as {} ", app.room, app.nick),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw("— Esc to quit — "),
        Span::styled(
            status,
            Style::default().fg(if failed { Color::Red } else { Color::DarkGray }),
        ),
    ]));
    f.render_widget(header, chunks[0]);

    // Newest last, and only what fits: the pane does not scroll.
    let height = chunks[1].height.saturating_sub(2) as usize;
    let messages = app.messages.lock().unwrap();
    let items: Vec<ListItem> = messages
        .iter()
        .rev()
        .take(height)
        .rev()
        .map(|m| ListItem::new(Line::from(m.as_str())))
        .collect();
    f.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title("Chat")),
        chunks[1],
    );

    f.render_widget(
        Paragraph::new(app.input.as_str())
            .block(Block::default().borders(Borders::ALL).title("Message")),
        chunks[2],
    );
    f.set_cursor_position((
        chunks[2].x + app.input.chars().count() as u16 + 1,
        chunks[2].y + 1,
    ));
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    println!("Starting logos-delivery node, this takes a few seconds...");
    let mut app = App::new(&cli).await?;
    app.start().await?;

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let res = run(&mut terminal, &mut app).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    app.stop().await;
    res
}
