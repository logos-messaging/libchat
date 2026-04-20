//! logos-delivery backed [`client::DeliveryService`] implementation.
//!
//! `LogosDeliveryService` wraps an embedded logos-delivery node running on a
//! dedicated `std::thread`. All interaction is via synchronous `std::sync::mpsc`
//! channels.
//!
//! ## Content topic mapping
//!
//! `AddressedEnvelope::delivery_address` maps to logos-delivery content topic
//! `/logos-chat/1/{delivery_address}/proto`.

pub(crate) mod sys;
pub(crate) mod wrapper;

use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use client::{AddressedEnvelope, DeliveryService};
use tracing::{error, info, warn};

use wrapper::LogosNodeCtx;

pub fn content_topic_for(delivery_address: &str) -> String {
    format!("/logos-chat/1/{delivery_address}/proto")
}

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    #[error("node startup failed: {0}")]
    StartupFailed(String),
    #[error("publish failed: {0}")]
    PublishFailed(String),
    #[error("send channel closed")]
    ChannelClosed,
}

// ── Internals ────────────────────────────────────────────────────────────────

struct OutboundCmd {
    message_json: String,
    reply: mpsc::SyncSender<Result<(), DeliveryError>>,
}

type SubscriberList = Arc<Mutex<Vec<mpsc::SyncSender<Vec<u8>>>>>;

// ── Config ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Config {
    pub preset: String,
    pub tcp_port: u16,
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            preset: "logos.dev".into(),
            tcp_port: 60000,
            log_level: "ERROR".into(),
        }
    }
}

// ── Wire types ──────────────────────────────────────────────────────────────

/// Outbound message sent to the logos-delivery node.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct WakuMessage {
    #[serde(rename = "contentTopic")]
    content_topic: String,
    /// Base64-encoded payload.
    payload: String,
    ephemeral: bool,
}

/// Top-level event envelope received from the logos-delivery node callback.
#[derive(Debug, serde::Deserialize)]
struct WakuEvent {
    #[serde(rename = "eventType")]
    event_type: String,
    message: Option<ReceivedMessage>,
}

/// Message payload from a `message_received` event.
#[derive(Debug, serde::Deserialize)]
struct ReceivedMessage {
    #[serde(rename = "contentTopic")]
    content_topic: String,
    /// The node may deliver the payload as either a base64 string or a JSON
    /// array of byte values.
    payload: WakuPayload,
}

/// Untagged union that handles both payload representations.
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum WakuPayload {
    Base64(String),
    Bytes(Vec<u8>),
}

impl WakuPayload {
    fn decode(self) -> Option<Vec<u8>> {
        match self {
            WakuPayload::Base64(s) => BASE64.decode(s).ok(),
            WakuPayload::Bytes(b) => Some(b),
        }
    }
}

// ── Service ──────────────────────────────────────────────────────────────────

/// logos-delivery backed delivery service. Cheap to clone — all clones share
/// the same background node.
#[derive(Clone)]
pub struct Service {
    outbound: mpsc::SyncSender<OutboundCmd>,
    #[allow(dead_code)]
    subscribers: SubscriberList,
}

impl Service {
    /// Start the embedded logos-delivery node. Returns the service and a
    /// receiver for inbound raw payloads.
    pub fn start(cfg: Config) -> Result<(Self, mpsc::Receiver<Vec<u8>>), DeliveryError> {
        let (out_tx, out_rx) = mpsc::sync_channel::<OutboundCmd>(256);
        let subscribers: SubscriberList = Arc::new(Mutex::new(Vec::new()));
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), DeliveryError>>();
        // Create the inbound channel before spawning so the receiver is
        // registered inside the thread, before any event callback fires.
        let (inbound_tx, inbound_rx) = mpsc::sync_channel::<Vec<u8>>(1024);

        let subs_for_thread = subscribers.clone();

        let handle = thread::Builder::new()
            .name("logos-node".into())
            .spawn(move || {
                if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    Self::node_thread(cfg, out_rx, subs_for_thread, inbound_tx, ready_tx);
                })) {
                    let msg = panic
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown panic".into());
                    error!("logos-node thread panicked: {msg}");
                }
            })
            .map_err(|e| DeliveryError::StartupFailed(e.to_string()))?;

        // On failure, the node thread drops LogosNodeCtx (stop+destroy against
        // a half-initialized Nim node). Join it so the process doesn't begin
        // teardown mid-destroy — that race SIGSEGVs inside the Nim async loop.
        let ready = ready_rx.recv().unwrap_or_else(|_| {
            Err(DeliveryError::StartupFailed(
                "node thread exited before ready".into(),
            ))
        });
        if let Err(e) = ready {
            let _ = handle.join();
            return Err(e);
        }

        Ok((
            Self {
                outbound: out_tx,
                subscribers,
            },
            inbound_rx,
        ))
    }

    fn node_thread(
        cfg: Config,
        out_rx: mpsc::Receiver<OutboundCmd>,
        subscribers: SubscriberList,
        inbound_tx: mpsc::SyncSender<Vec<u8>>,
        ready_tx: mpsc::Sender<Result<(), DeliveryError>>,
    ) {
        // discv5UdpPort defaults to 9000 in libwaku, so a second instance with
        // a distinct --port still collides on UDP. Bind it to tcp_port so a
        // single --port knob keeps both ports distinct across instances.
        let config_json = serde_json::json!({
            "logLevel": cfg.log_level,
            "mode": "Core",
            "preset": cfg.preset,
            "tcpPort": cfg.tcp_port,
            "discv5UdpPort": cfg.tcp_port,
        })
        .to_string();

        let mut node = match LogosNodeCtx::new(&config_json) {
            Ok(n) => n,
            Err(e) => {
                let _ = ready_tx.send(Err(DeliveryError::StartupFailed(e)));
                return;
            }
        };

        // Register the inbound sender before installing the event callback so
        // there is no window where the callback is live but the channel is not
        // yet in the subscriber list.
        subscribers.lock().unwrap().push(inbound_tx);

        let subs_for_cb = subscribers.clone();
        let event_closure = move |_ret: i32, data: &str| {
            if let Some(payload) = Self::parse_message_received(data) {
                let mut guard = match subs_for_cb.lock() {
                    Ok(g) => g,
                    Err(e) => {
                        error!("subscriber mutex poisoned: {e}");
                        return;
                    }
                };
                guard.retain(|tx| match tx.try_send(payload.clone()) {
                    Ok(()) => true,
                    Err(mpsc::TrySendError::Full(_)) => true,
                    Err(mpsc::TrySendError::Disconnected(_)) => false,
                });
            }
        };
        node.set_event_callback(event_closure);

        if let Err(e) = node.start() {
            let _ = ready_tx.send(Err(DeliveryError::StartupFailed(e)));
            return;
        }
        info!("logos-delivery node started (preset={})", cfg.preset);

        // FIXME: This unconditional sleep is a stand-in for proper
        // peer-connectivity detection. The right approach is to listen for a
        // `peer_connected` (or equivalent status-change) event from the node
        // callback and only proceed once at least one peer is reachable,
        // falling back to a configurable timeout. logos-delivery would need to
        // surface such an event via its callback mechanism for this to work.
        thread::sleep(Duration::from_secs(3));

        let default_topic = content_topic_for("delivery_address");
        if let Err(e) = node.subscribe(&default_topic) {
            warn!("subscribe to {default_topic}: {e}");
        } else {
            info!("subscribed to {default_topic}");
        }

        let _ = ready_tx.send(Ok(()));

        while let Ok(cmd) = out_rx.recv() {
            let result = node
                .send(&cmd.message_json)
                .map(|_| ())
                .map_err(DeliveryError::PublishFailed);
            let _ = cmd.reply.try_send(result);
        }

        info!("logos-node outbound loop finished");
    }

    fn parse_message_received(data: &str) -> Option<Vec<u8>> {
        let event: WakuEvent = serde_json::from_str(data).ok()?;

        if event.event_type != "message_received" {
            return None;
        }

        let msg = event.message?;

        if !msg.content_topic.starts_with("/logos-chat/1/") {
            return None;
        }

        msg.payload.decode()
    }
}

impl DeliveryService for Service {
    type Error = DeliveryError;

    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), DeliveryError> {
        let msg = WakuMessage {
            content_topic: content_topic_for(&envelope.delivery_address),
            payload: BASE64.encode(&envelope.data),
            ephemeral: false,
        };
        let message_json =
            serde_json::to_string(&msg).map_err(|e| DeliveryError::PublishFailed(e.to_string()))?;

        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.outbound
            .send(OutboundCmd {
                message_json,
                reply: reply_tx,
            })
            .map_err(|_| DeliveryError::ChannelClosed)?;

        reply_rx.recv().map_err(|_| DeliveryError::ChannelClosed)?
    }
}
