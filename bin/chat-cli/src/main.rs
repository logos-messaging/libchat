mod app;
mod transport;
mod ui;
mod utils;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use client::DeliveryService;

use app::ChatApp;

#[derive(Parser, Debug)]
#[command(name = "chat-cli", about = "End-to-end encrypted terminal chat")]
struct Cli {
    /// Your identity name.
    #[arg(long, short)]
    name: String,

    // ── File-transport options ────────────────────────────────────────────────
    /// Shared data directory for file transport (both peers must use the same path).
    #[arg(long, default_value = "tmp/chat-cli-data")]
    data: PathBuf,

    // ── logos-delivery transport options ──────────────────────────────────────
    /// Persistent SQLite database for logos-delivery transport (omit for ephemeral identity).
    #[arg(long)]
    db: Option<PathBuf>,

    /// logos-delivery network preset (`logos.dev` or `twn`).
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
    #[cfg(logos_delivery)]
    return run_logos_delivery(cli);
    #[cfg(not(logos_delivery))]
    run_file(cli)
}

#[cfg(not(logos_delivery))]
fn run_file(cli: Cli) -> Result<()> {
    use transport::file::FileTransport;

    std::fs::create_dir_all(&cli.data).context("failed to create data directory")?;

    println!("Starting chat as '{}'...", cli.name);
    println!("Data dir: {}", cli.data.display());

    let transport_dir = cli.data.join("transport");
    let (transport, inbound) =
        FileTransport::new(&transport_dir).context("failed to create file transport")?;

    let db_path = cli.data.join(format!("{}.db", cli.name));
    let client = client::ChatClient::open(
        cli.name.clone(),
        client::StorageConfig::Encrypted {
            path: db_path.to_string_lossy().to_string(),
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
        let (delivery, inbound) =
            Service::start(logos_cfg).context("failed to start logos-delivery")?;

        eprintln!("Node connected. Initializing chat client...");

        let data_dir = cli
            .db
            .as_ref()
            .and_then(|p| p.parent())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| cli.data.clone());

        let client = match cli.db {
            Some(ref path) => {
                let db_str = path
                    .to_str()
                    .context("db path contains non-UTF-8 characters")?
                    .to_string();
                client::ChatClient::open(
                    cli.name.clone(),
                    client::StorageConfig::Encrypted {
                        path: db_str,
                        key: "chat-cli".to_string(),
                    },
                    delivery,
                )
                .map_err(|e| anyhow::anyhow!("{e:?}"))
                .context("failed to open persistent client")?
            }
            None => client::ChatClient::new(cli.name.clone(), delivery),
        };

        let mut app = ChatApp::new(client, inbound, &cli.name, &data_dir)?;

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

fn setup_logging(log_file: Option<&std::path::Path>) -> Result<()> {
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
