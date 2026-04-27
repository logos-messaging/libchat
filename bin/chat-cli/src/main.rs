mod app;
mod transport;
mod ui;
mod utils;

use std::path::{Path, PathBuf};
use std::sync::mpsc;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use client::DeliveryService;

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
    #[arg(long, value_enum, default_value_t = TransportKind::LogosDelivery)]
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    setup_logging(cli.log_file.as_deref())?;

    std::fs::create_dir_all(&cli.data).context("failed to create data directory")?;

    match cli.transport {
        TransportKind::File => {
            let transport_dir = cli.data.join("transport");
            let (transport, inbound) = transport::file::FileTransport::new(&transport_dir)
                .context("failed to create file transport")?;
            run(transport, inbound, &cli)
        }
        TransportKind::LogosDelivery => {
            use transport::logos_delivery::{Config, Service};

            eprintln!("Starting logos-delivery node (preset={})...", cli.preset);
            eprintln!("This may take a few seconds while connecting to the network.");

            let cfg = Config {
                preset: cli.preset.clone(),
                tcp_port: cli.port,
                ..Default::default()
            };
            let (transport, inbound) =
                Service::start(cfg).context("failed to start logos-delivery")?;

            eprintln!("Node connected. Initializing chat client...");
            run(transport, inbound, &cli)
        }
    }
}

fn run<D: DeliveryService>(
    transport: D,
    inbound: mpsc::Receiver<Vec<u8>>,
    cli: &Cli,
) -> Result<()> {
    let db_path = cli
        .db
        .clone()
        .unwrap_or_else(|| cli.data.join(format!("{}.db", cli.name)));
    let db_str = db_path
        .to_str()
        .context("db path contains non-UTF-8 characters")?
        .to_string();

    let client = client::ChatClient::open(
        cli.name.clone(),
        client::StorageConfig::Encrypted {
            path: db_str,
            key: "chat-cli".to_string(),
        },
        transport,
    )
    .map_err(|e| anyhow::anyhow!("{e:?}"))
    .context("failed to open chat client")?;

    let mut app = ChatApp::new(client, inbound, &cli.name, &cli.data)?;

    if cli.smoketest {
        return Ok(());
    }

    let mut terminal = ui::init().context("failed to initialize terminal")?;
    let result = run_app(&mut terminal, &mut app);
    ui::restore().context("failed to restore terminal")?;
    result
}

fn run_app<D: DeliveryService>(terminal: &mut ui::Tui, app: &mut ChatApp<D>) -> Result<()> {
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
