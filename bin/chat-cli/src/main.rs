mod app;
mod transport;
mod ui;
mod utils;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use crossbeam_channel::Receiver;
use logos_chat::{ChatClient, Event, HttpRegistry, RegistrationService, StorageConfig, Transport};

use app::ChatApp;

#[derive(Copy, Clone, Debug, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum TransportKind {
    File,
    #[cfg(logos_delivery)]
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
        #[cfg(logos_delivery)]
        TransportKind::LogosDelivery => {
            use transport::logos_delivery::{Config, Service};

            println!("Starting logos-delivery node (preset={})...", cli.preset);
            println!("This may take a few seconds while connecting to the network.");

            let cfg = Config {
                preset: cli.preset.clone(),
                tcp_port: cli.port,
                ..Default::default()
            };
            let transport = Service::start(cfg).context("failed to start logos-delivery")?;

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
            let (client, events) =
                ChatClient::open_with_registry(cli.name.clone(), storage, transport, registry)
                    .map_err(|e| anyhow::anyhow!("{e:?}"))
                    .context("failed to open chat client with HTTP registry")?;
            launch_tui(client, events, cli)
        }
        None => {
            let (client, events) = ChatClient::open(cli.name.clone(), storage, transport)
                .map_err(|e| anyhow::anyhow!("{e:?}"))
                .context("failed to open chat client")?;
            launch_tui(client, events, cli)
        }
    }
}

fn launch_tui<T, R>(client: ChatClient<T, R>, events: Receiver<Event>, cli: &Cli) -> Result<()>
where
    T: Transport,
    R: RegistrationService + Send + 'static,
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

#[cfg_attr(not(logos_delivery), allow(dead_code, unused_variables))]
fn run_logos_delivery(cli: Cli) -> Result<()> {
    #[cfg(logos_delivery)]
    {
        use transport::logos_delivery::{Config, Service};

        eprintln!("Starting logos-delivery node (preset={})...", cli.preset);
        eprintln!("This may take a few seconds while connecting to the network.");

        let logos_cfg = Config {
            preset: cli.preset.clone(),
            tcp_port: cli.port,
            ..Default::default()
        };
        let delivery = Service::start(logos_cfg).context("failed to start logos-delivery")?;

        eprintln!("Node connected. Initializing chat client...");

        let data_dir = cli
            .db
            .as_ref()
            .and_then(|p| p.parent())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| cli.data.clone());

        let (client, events) = match cli.db {
            Some(ref path) => {
                let db_str = path
                    .to_str()
                    .context("db path contains non-UTF-8 characters")?
                    .to_string();
                logos_chat::ChatClient::open(
                    cli.name.clone(),
                    logos_chat::StorageConfig::Encrypted {
                        path: db_str,
                        key: "chat-cli".to_string(),
                    },
                    delivery,
                )
                .map_err(|e| anyhow::anyhow!("{e:?}"))
                .context("failed to open persistent client")?
            }
            None => logos_chat::ChatClient::new(cli.name.clone(), delivery),
        };

        let mut app = ChatApp::new(client, events, &cli.name, &data_dir)?;

        if cli.smoketest {
            return Ok(());
        }

        let mut terminal = ui::init().context("failed to initialize terminal")?;
        let result = run_app(&mut terminal, &mut app);
        ui::restore().context("failed to restore terminal")?;
        return result;
    }

    #[cfg(not(logos_delivery))]
    anyhow::bail!(
        "logos-delivery transport is not available in this build.\n\
         Build with LOGOS_DELIVERY_LIB_DIR set to enable it."
    )
}

fn run_app<T, R>(terminal: &mut ui::Tui, app: &mut ChatApp<T, R>) -> Result<()>
where
    T: Transport,
    R: RegistrationService + Send + 'static,
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
