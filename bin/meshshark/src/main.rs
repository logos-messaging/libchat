//! meshshark — a sniffer for logos-delivery networks.
//!
//! Starts an embedded logos-delivery node, subscribes to one content topic per
//! `--sub` delivery address, and shows arriving-message metadata live: either a
//! pane per subscription (grid) or a single merged stream (unified), toggled at
//! runtime. Each line shows the delta from start, a color-coded topic, and the
//! payload size.

mod ui;

use std::io::{self, Stdout};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use logos_delivery::{P2pConfig, ThreadedDeliveryWrapper, WakuEvent};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use ui::{App, InputMode, ObservedMessage, Pane};

/// The content-topic template logos-chat traffic uses.
fn content_topic_for(delivery_address: &str) -> String {
    format!("/logos-chat/1/{delivery_address}/proto")
}

/// FNV-1a hash of the payload, used as a message id to spot duplicate deliveries.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    }
    h
}

#[derive(Parser, Debug)]
#[command(
    name = "meshshark",
    about = "See what is happening on a logos-delivery network"
)]
struct Cli {
    /// Topic to watch (repeatable). One pane each. A value starting with `/`
    /// is used as a full content topic; otherwise it is treated as a delivery
    /// address and wrapped as /logos-chat/1/<address>/proto.
    #[arg(long = "sub", short = 's', value_name = "ADDRESS|TOPIC")]
    subs: Vec<String>,

    /// Add a firehose pane showing every message the node receives, on any
    /// content topic (not just the --sub topics). You still need at least one
    /// --sub to join a shard and receive anything.
    #[arg(long)]
    all: bool,

    /// logos-delivery network preset.
    #[arg(long, default_value = "logos.dev")]
    preset: String,

    /// Node log level (kept quiet by default so it doesn't corrupt the TUI).
    #[arg(long, default_value = "ERROR")]
    log_level: String,

    /// TCP/UDP port for the node. Defaults to an OS-assigned free port so
    /// multiple instances can run side by side.
    #[arg(long)]
    port: Option<u16>,
}

type Tui = Terminal<CrosstermBackend<Stdout>>;
type Delivery = ThreadedDeliveryWrapper<ObservedMessage>;

fn main() {
    let cli = Cli::parse();

    let port = match cli.port {
        Some(p) => p,
        None => match free_port() {
            Ok(p) => p,
            Err(e) => fatal(&format!("could not find a free port: {e}")),
        },
    };

    eprintln!(
        "meshshark: starting logos-delivery node (preset={}, port={})…",
        cli.preset, port
    );

    // Map each raw event to an ObservedMessage on the node callback thread:
    // stamp arrival time, keep the topic, and measure the payload — the UI
    // never needs the bytes themselves.
    let start_cfg = P2pConfig {
        preset: cli.preset.clone(),
        port,
        log_level: cli.log_level.clone(),
    };
    let mut delivery = match ThreadedDeliveryWrapper::start(start_cfg, |event: WakuEvent| {
        let msg = event.into_received()?;
        let content_topic = msg.content_topic().to_string();
        let payload = msg.into_payload().unwrap_or_default();
        Some(ObservedMessage {
            received_at: Instant::now(),
            content_topic,
            payload_len: payload.len(),
            message_id: fnv1a_64(&payload),
        })
    }) {
        Ok(d) => d,
        Err(e) => fatal(&format!("failed to start logos-delivery node: {e}")),
    };
    let inbound = delivery.inbound_queue();

    // Once the node exists we never drop it: its Drop runs a blocking
    // stop+destroy that can hang, and its background threads swallow Ctrl-C. So
    // from here on, every exit goes through process::exit while `delivery` is
    // still a live local — the OS reclaims the node at process exit.
    let mut panes = Vec::with_capacity(cli.subs.len() + usize::from(cli.all));
    if cli.all {
        panes.push(Pane::catch_all());
    }
    for sub in &cli.subs {
        let topic = topic_for(sub);
        if let Err(e) = delivery.subscribe(&topic) {
            fatal(&format!("failed to subscribe to {sub}: {e}"));
        }
        panes.push(Pane::new(sub.clone(), topic));
    }

    let app = App::new(panes, port, cli.preset);

    let mut terminal = match setup_terminal() {
        Ok(t) => t,
        Err(e) => fatal(&format!("failed to set up terminal: {e}")),
    };
    // On a quit key `run` restores the terminal and exits the process itself;
    // it only returns here on a render/IO error.
    if let Err(e) = run(&mut terminal, &delivery, &inbound, app) {
        let _ = restore_terminal(&mut terminal);
        fatal(&format!("{e:?}"));
    }
}

/// Restore the terminal and terminate the process immediately. We use `_exit`
/// rather than `process::exit`: the embedded Nim/libwaku runtime installs
/// `atexit` handlers that block on node teardown, so `process::exit` — which
/// runs them — hangs forever. `_exit` is the raw syscall and skips all of them.
fn quit(terminal: &mut Tui) -> ! {
    let _ = restore_terminal(terminal);
    unsafe { libc::_exit(0) };
}

/// Print a message and terminate the process immediately. Uses `_exit` for the
/// same reason as [`quit`]: once the node exists, `process::exit` hangs in the
/// Nim runtime's `atexit` handlers. stderr is unbuffered, so the message is
/// already flushed before the syscall.
fn fatal(msg: &str) -> ! {
    eprintln!("meshshark: {msg}");
    unsafe { libc::_exit(1) };
}

fn run(
    terminal: &mut Tui,
    delivery: &Delivery,
    inbound: &crossbeam_channel::Receiver<ObservedMessage>,
    mut app: App,
) -> Result<()> {
    loop {
        terminal.draw(|f| ui::draw(f, &app))?;

        // Drain everything observed since the last frame.
        while let Ok(msg) = inbound.try_recv() {
            app.record(msg);
        }

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            // Ctrl-C always quits, whatever the mode.
            if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                quit(terminal);
            }
            match &mut app.mode {
                InputMode::Normal => match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => quit(terminal),
                    KeyCode::Char('v') | KeyCode::Tab => app.toggle_view(),
                    KeyCode::Char('a') => {
                        app.status.clear();
                        app.mode = InputMode::Adding(String::new());
                    }
                    _ => {}
                },
                InputMode::Adding(buffer) => match key.code {
                    KeyCode::Esc => app.mode = InputMode::Normal,
                    KeyCode::Char(c) => buffer.push(c),
                    KeyCode::Backspace => {
                        buffer.pop();
                    }
                    KeyCode::Enter => {
                        let address = buffer.trim().to_string();
                        app.mode = InputMode::Normal;
                        add_subscription(delivery, &mut app, address);
                    }
                    _ => {}
                },
            }
        }
    }
}

/// Resolve a `--sub`/input value to a content topic. A value beginning with
/// `/` is already a content topic and used verbatim; anything else is treated
/// as a delivery address and wrapped.
fn topic_for(input: &str) -> String {
    if input.starts_with('/') {
        input.to_string()
    } else {
        content_topic_for(input)
    }
}

/// Subscribe to an address or topic entered at runtime, reporting the outcome
/// in the status bar.
fn add_subscription(delivery: &Delivery, app: &mut App, input: String) {
    if input.is_empty() {
        return;
    }
    let topic = topic_for(&input);
    if app.has_topic(&topic) {
        app.status = format!("already watching {topic}");
        return;
    }
    match delivery.subscribe(&topic) {
        Ok(()) => {
            app.push_pane(input, topic.clone());
            app.status = format!("subscribed to {topic}");
        }
        Err(e) => app.status = format!("subscribe to {topic} failed: {e}"),
    }
}

/// Ask the OS for an unused port. Binding to port 0 yields a free TCP port;
/// the node reuses it for UDP too, which is effectively free right after.
fn free_port() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

fn setup_terminal() -> Result<Tui> {
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(io::stdout());
    Ok(Terminal::new(backend)?)
}

fn restore_terminal(terminal: &mut Tui) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
