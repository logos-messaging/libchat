mod app;
mod transport;
mod ui;
mod utils;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use crossbeam_channel::Receiver;
use logos_account::TestLogosAccount;
use logos_chat::{
    AccountDirectory, ChatClient, ChatClientBuilder, ChatStore, DelegateSigner, Event,
    HttpRegistry, LogosChatClient, LogosConfig, NETWORK_PRESET, REGISTRY_ENDPOINT,
    RegistrationService, StorageConfig, Transport,
};

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
    /// logos-delivery network preset (e.g. `logos.dev`). When omitted, the
    /// preconfigured network preset is used.
    #[arg(long)]
    preset: Option<String>,

    /// TCP port for the embedded logos-delivery node. When omitted, the
    /// preconfigured port is used.
    #[arg(long)]
    port: Option<u16>,

    /// Write logs to a file instead of stderr (keeps TUI output clean).
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Initialize and immediately exit without launching the TUI (for CI).
    #[arg(long)]
    smoketest: bool,

    /// Override the Logos registry endpoint (account + keypackage store). When
    /// omitted, the preconfigured endpoint is used.
    /// Example: `--registry-url http://127.0.0.1:18080`.
    #[arg(long)]
    registry_url: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    setup_logging(cli.log_file.as_deref())?;

    std::fs::create_dir_all(&cli.data).context("failed to create data directory")?;

    let db_str = db_path(&cli)?;

    match cli.transport {
        // logos-delivery is the transport baked into `LogosChatClient`, so the
        // Logos client opens it from config rather than receiving one.
        TransportKind::LogosDelivery => {
            let preset = cli.preset.as_deref().unwrap_or(NETWORK_PRESET);
            println!("Starting logos-delivery node (preset={preset})...");
            println!("This may take a few seconds while connecting to the network.");

            let mut config = LogosConfig::new(db_str, "chat-cli");
            if let Some(port) = cli.port {
                config.set_tcp_port(port);
            }
            if let Some(preset) = cli.preset.as_deref() {
                config.set_preset(preset);
            }
            if let Some(registry_url) = cli.registry_url.as_deref() {
                config.set_registry_url(registry_url);
            }
            let (client, events) = LogosChatClient::open(config)
                .map_err(|e| anyhow::anyhow!("{e:?}"))
                .context("failed to open chat client")?;

            println!("Node connected.");
            launch_tui(client, events, &cli)
        }
        // The file transport is a local-only path: it reuses the Logos service
        // stack (delegate identity, HTTP registry, encrypted storage) but swaps
        // the transport, so it builds a client directly instead of going through
        // `LogosChatClient`.
        TransportKind::File => {
            let transport_dir = cli.data.join("transport");
            let transport = transport::file::FileTransport::new(&transport_dir)
                .context("failed to create file transport")?;

            let endpoint = cli.registry_url.as_deref().unwrap_or(REGISTRY_ENDPOINT);
            // A fresh dev account endorsing a fresh delegate each launch,
            // mirroring `LogosChatClient::open`.
            let account = TestLogosAccount::new();
            let delegate = DelegateSigner::random();
            let mut registry = HttpRegistry::new(endpoint);
            account
                .add_delegate_signer(&mut registry, delegate.public_key())
                .map_err(|e| anyhow::anyhow!("{e:?}"))
                .context("failed to publish the device bundle")?;
            let (client, events) = ChatClientBuilder::new(account.address())
                .ident(delegate)
                .transport(transport)
                .registration(registry)
                .storage_config(StorageConfig::Encrypted {
                    path: db_str,
                    key: "chat-cli".to_string(),
                })
                .build()
                .map_err(|e| anyhow::anyhow!("{e:?}"))
                .context("failed to open chat client")?;

            launch_tui(client, events, &cli)
        }
    }
}

/// Resolve the SQLite database path: `--db` if given, else `<data>/<name>.db`.
fn db_path(cli: &Cli) -> Result<String> {
    let path = cli
        .db
        .clone()
        .unwrap_or_else(|| cli.data.join(format!("{}.db", cli.name)));
    Ok(path
        .to_str()
        .context("db path contains non-UTF-8 characters")?
        .to_string())
}

fn launch_tui<T, R, S>(
    client: ChatClient<T, R, S>,
    events: Receiver<Event>,
    cli: &Cli,
) -> Result<()>
where
    T: Transport,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
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

fn run_app<T, R, S>(terminal: &mut ui::Tui, app: &mut ChatApp<T, R, S>) -> Result<()>
where
    T: Transport,
    R: RegistrationService + AccountDirectory + Clone + Send + 'static,
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
