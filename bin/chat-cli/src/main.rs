mod app;
mod transport;
mod ui;
mod utils;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use crossbeam_channel::Receiver;
use logos_chat::{
    ChatClient, ChatClientBuilder, ChatStore, Event, HttpRegistry, IdentityProvider,
    RegistrationService, StorageConfig, Transport,
};

use components::{EmbeddedP2pDeliveryService, P2pConfig};

#[derive(Debug)]
struct P2pTransport(EmbeddedP2pDeliveryService);

impl logos_chat::DeliveryService for P2pTransport {
    type Error = <EmbeddedP2pDeliveryService as logos_chat::DeliveryService>::Error;
    fn publish(&mut self, envelope: logos_chat::AddressedEnvelope) -> Result<(), Self::Error> {
        self.0.publish(envelope)
    }
    fn subscribe(&mut self, addr: &str) -> Result<(), Self::Error> {
        self.0.subscribe(addr)
    }
}

impl logos_chat::Transport for P2pTransport {
    fn inbound(&mut self) -> crossbeam_channel::Receiver<Vec<u8>> {
        self.0.inbound_queue()
    }
}

use app::ChatApp;

#[derive(Copy, Clone, Debug, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum TransportKind {
    File,
    LogosDelivery,
}

#[derive(Parser, Debug)]
#[command(name = "chat-cli", about = "End-to-end encrypted terminal chat")]
struct Cli {
    /// Your identity name.
    #[arg(long, short)]
    name: String,

    /// Which delivery transport to use.
    #[arg(long, value_enum, default_value_t = TransportKind::File)]
    transport: TransportKind,

    /// Data directory (used for UI state and the default SQLite path).
    #[arg(long, default_value = "tmp/chat-cli-data")]
    data: PathBuf,

    /// Override the SQLite database path (defaults to `<data>/<name>.db`).
    #[arg(long)]
    db: Option<PathBuf>,

    // ── logos-delivery transport options ──────────────────────────────────────
    /// logos-delivery network preset (e.g. `logos.dev`).
    #[arg(long, default_value = "logos.dev")]
    preset: String,

    /// TCP port for the embedded logos-delivery node.
    #[arg(long, default_value_t = 60000)]
    port: u16,

    /// Write logs to a file instead of stderr (keeps TUI output clean).
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Initialize and immediately exit without launching the TUI (for CI).
    #[arg(long)]
    smoketest: bool,

    /// Optional KeyPackage registry base URL. When set, uses the HTTP-backed
    /// registry instead of the in-memory `EphemeralRegistry`.
    /// Example: `--registry-url http://localhost:8080`.
    #[arg(long)]
    registry_url: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    setup_logging(cli.log_file.as_deref())?;

    std::fs::create_dir_all(&cli.data).context("failed to create data directory")?;

    match cli.transport {
        TransportKind::File => {
            let transport_dir = cli.data.join("transport");
            let transport = transport::file::FileTransport::new(&transport_dir)
                .context("failed to create file transport")?;
            run(transport, &cli)
        }
        TransportKind::LogosDelivery => {
            println!("Starting logos-delivery node (preset={})...", cli.preset);
            println!("This may take a few seconds while connecting to the network.");

            let cfg = P2pConfig {
                preset: cli.preset.clone(),
                tcp_port: cli.port,
                ..Default::default()
            };
            let transport = P2pTransport(
                EmbeddedP2pDeliveryService::start(cfg).context("failed to start logos-delivery")?,
            );

            println!("Node connected. Initializing chat client...");
            run(transport, &cli)
        }
    }
}

fn run<T: Transport>(transport: T, cli: &Cli) -> Result<()> {
    let db_path = cli
        .db
        .clone()
        .unwrap_or_else(|| cli.data.join(format!("{}.db", cli.name)));
    let db_str = db_path
        .to_str()
        .context("db path contains non-UTF-8 characters")?
        .to_string();
    let storage = StorageConfig::Encrypted {
        path: db_str,
        key: "chat-cli".to_string(),
    };

    match cli.registry_url.as_deref() {
        Some(url) => {
            let registry = HttpRegistry::new(url);
            let (client, events) = ChatClientBuilder::new()
                .transport(transport)
                .storage_config(storage)
                .registration(registry)
                .build()
                .map_err(|e| anyhow::anyhow!("{e:?}"))
                .context("failed to open chat client with HTTP registry")?;
            launch_tui(client, events, cli)
        }
        None => {
            let (client, events) = ChatClientBuilder::new()
                .transport(transport)
                .storage_config(storage)
                .build()
                .map_err(|e| anyhow::anyhow!("{e:?}"))
                .context("failed to open chat client")?;
            launch_tui(client, events, cli)
        }
    }
}

fn launch_tui<I, T, R, S>(
    client: ChatClient<I, T, R, S>,
    events: Receiver<Event>,
    cli: &Cli,
) -> Result<()>
where
    I: IdentityProvider + Send,
    T: Transport,
    R: RegistrationService + Send + 'static,
    S: ChatStore + Send,
{
    let mut app = ChatApp::new(client, events, &cli.name, &cli.data)?;

    if cli.smoketest {
        return Ok(());
    }

    let mut terminal = ui::init().context("failed to initialize terminal")?;
    let result = run_app(&mut terminal, &mut app);
    ui::restore().context("failed to restore terminal")?;
    result
}

fn run_app<I, T, R, S>(terminal: &mut ui::Tui, app: &mut ChatApp<I, T, R, S>) -> Result<()>
where
    I: IdentityProvider + Send,
    T: Transport,
    R: RegistrationService + Send + 'static,
    S: ChatStore + Send,
{
    loop {
        app.process_incoming()?;
        terminal.draw(|frame| ui::draw(frame, app))?;
        if !ui::handle_events(app)? {
            break;
        }
    }
    Ok(())
}

fn setup_logging(log_file: Option<&Path>) -> Result<()> {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));

    if let Some(path) = log_file {
        let file = std::fs::File::create(path)
            .with_context(|| format!("failed to create log file: {}", path.display()))?;
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(file)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new("off"))
            .init();
    }

    Ok(())
}
