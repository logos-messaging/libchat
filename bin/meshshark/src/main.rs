use std::time::{Duration, Instant};

use logos_delivery::{DeliveryError, P2pConfig, ThreadedDeliveryWrapper};
use tracing::info;

fn run() -> Result<(), DeliveryError> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();

    let mut cfg = P2pConfig::default();
    cfg.log_level = "DEBUG".into();
    cfg.tcp_port = 60012;

    let mut ld = ThreadedDeliveryWrapper::start(cfg, |x| Some(x))?;
    let inbound = ld.inbound_queue();

    ld.subscribe("/logos-chat/1/ping/proto")?;

    // Print each received message until the deadline.
    let deadline = Instant::now() + Duration::from_secs(40);
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let Ok(event) = inbound.recv_timeout(remaining) else {
            break; // timeout or channel closed
        };
        let Some(msg) = event.into_received() else {
            continue; // non-message event
        };
        let topic = msg.content_topic().to_string();
        let payload = msg.into_payload().unwrap_or_default();
        info!(topic, "recv: {}", String::from_utf8_lossy(&payload));
    }

    Ok(())
}

fn main() {
    run().unwrap()
}
