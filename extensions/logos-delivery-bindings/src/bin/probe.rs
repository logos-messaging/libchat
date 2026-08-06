//! Manual end-to-end check: starts a node, subscribes, optionally publishes,
//! and prints whatever arrives on the inbound queue.
//!
//! Run two instances on different ports to watch a message cross the network:
//!
//! ```sh
//! cargo run --bin probe -- --port 60010
//! cargo run --bin probe -- --port 60020 --send "hello"
//! ```

use std::time::Duration;

use logos_delivery_bindings::{P2pConfig, ThreadedDeliveryWrapper, WakuEvent};

const CHAT_TOPIC_PREFIX: &str = "/logos-chat/1/";

fn content_topic_for(delivery_address: &str) -> String {
    format!("{CHAT_TOPIC_PREFIX}{delivery_address}/proto")
}

struct Args {
    port: u16,
    address: String,
    send: Option<String>,
    send_after: u64,
    linger: u64,
    log_level: String,
}

fn parse_args() -> Args {
    let mut args = Args {
        port: 60010,
        address: "bindings-probe".into(),
        send: None,
        send_after: 8,
        linger: 20,
        log_level: "ERROR".into(),
    };
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut value = || {
            argv.next()
                .unwrap_or_else(|| panic!("{flag} needs a value"))
        };
        match flag.as_str() {
            "--port" => args.port = value().parse().expect("--port must be a u16"),
            "--address" => args.address = value(),
            "--send" => args.send = Some(value()),
            "--send-after" => args.send_after = value().parse().expect("--send-after is seconds"),
            "--linger" => args.linger = value().parse().expect("--linger must be seconds"),
            "--log-level" => args.log_level = value(),
            other => panic!("unknown flag: {other}"),
        }
    }
    args
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();
    let topic = content_topic_for(&args.address);

    let cfg = P2pConfig {
        port: args.port,
        log_level: args.log_level.clone(),
        ..P2pConfig::default()
    };
    println!("[probe] starting node on port {}", cfg.port);

    let mut delivery = ThreadedDeliveryWrapper::start(cfg, |event: WakuEvent| {
        let msg = event.into_received()?;
        if !msg.content_topic().starts_with(CHAT_TOPIC_PREFIX) {
            return None;
        }
        msg.into_payload()
    })?;

    let inbound = delivery.inbound_queue();

    println!("[probe] subscribe {topic}");
    delivery.subscribe(&topic)?;

    if let Some(text) = &args.send {
        // Publishing too soon after start can reach only this node: `start`
        // waits a fixed 3s, which need not be long enough for the mesh.
        println!("[probe] waiting {}s for the mesh to form", args.send_after);
        std::thread::sleep(Duration::from_secs(args.send_after));
        println!("[probe] publish {text:?}");
        delivery.publish(&topic, text.as_bytes())?;
    }

    println!("[probe] listening for {}s", args.linger);
    let deadline = std::time::Instant::now() + Duration::from_secs(args.linger);
    while let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) {
        match inbound.recv_timeout(remaining) {
            Ok(bytes) => println!(
                "[probe] received {} bytes: {}",
                bytes.len(),
                String::from_utf8_lossy(&bytes)
            ),
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => break,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                println!("[probe] inbound queue disconnected");
                break;
            }
        }
    }

    println!("[probe] unsubscribe + shut down");
    delivery.unsubscribe(&topic)?;
    // Node teardown (stop + destroy) happens when the last clone drops.
    Ok(())
}
