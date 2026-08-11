//! An embedded logos-delivery node, driven through the `waku-bindings` FFI.
//!
//! [`ThreadedDeliveryWrapper`] starts the node, publishes and subscribes by
//! content topic, and hands mapped inbound messages back on a queue.
//!
//! There is no node thread: `LogosDeliveryCtx` is `Send + Sync` and serialises
//! calls internally, so operations run on the caller's thread and the wrapper
//! is an `Arc` handle plus the queue.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use crossbeam_channel::Receiver;
use tracing::{debug, error, info, warn};
use waku_bindings::{LogosDeliveryCtx, MessageReceivedPayload, SendRequest, WakuMessagePayload};

/// `LogosDeliveryCtx` stores this at creation and reuses it for every call.
const NODE_CALL_TIMEOUT: Duration = Duration::from_secs(30);

const INBOUND_CAPACITY: usize = 1024;

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    #[error("node startup failed: {0}")]
    StartupFailed(String),
    #[error("publish failed: {0}")]
    PublishFailed(String),
    #[error("subscribe failed: {0}")]
    SubscribeFailed(String),
    #[error("unsubscribe failed: {0}")]
    UnsubscribeFailed(String),
    #[error("send channel closed")]
    ChannelClosed,
}

// ── P2pConfig ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct P2pConfig {
    pub preset: String,
    pub port: u16,
    pub log_level: String,
}

impl Default for P2pConfig {
    /// Joins `logos.dev` on an OS-assigned port, so instances do not collide.
    fn default() -> Self {
        const DEFAULT_NETWORK_PRESET: &str = "logos.dev";
        const DEFAULT_PORT: u16 = 0;
        Self {
            preset: DEFAULT_NETWORK_PRESET.into(),
            port: DEFAULT_PORT,
            log_level: "ERROR".into(),
        }
    }
}

impl P2pConfig {
    /// The node config JSON handed to `LogosDeliveryCtx::create`.
    fn to_json(&self) -> String {
        // discv5UdpPort defaults to 9000 in libwaku, so a second instance with
        // a distinct --port still collides on UDP. Bind it to tcp_port so a
        // single --port knob keeps both ports distinct across instances.
        serde_json::json!({
            "logLevel": self.log_level,
            "mode": "Core",
            "preset": self.preset,
            "tcpPort": self.port,
            "discv5UdpPort": self.port,
        })
        .to_string()
    }
}

// ── Wire types ──────────────────────────────────────────────────────────────

/// A received-message event from the node.
#[derive(Debug, Clone)]
pub struct WakuEvent {
    message: WakuMessagePayload,
}

impl WakuEvent {
    /// The received message. Always `Some`: the listener only fires for this
    /// one event, so there is nothing to narrow.
    pub fn into_received(self) -> Option<ReceivedMessage> {
        Some(ReceivedMessage {
            message: self.message,
        })
    }
}

/// Message payload from a received-message event.
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    message: WakuMessagePayload,
}

impl ReceivedMessage {
    pub fn content_topic(&self) -> &str {
        &self.message.content_topic
    }

    /// Decode the base64 payload to raw bytes.
    pub fn into_payload(self) -> Option<Vec<u8>> {
        BASE64.decode(self.message.payload).ok()
    }
}

// ── Node ────────────────────────────────────────────────────────────────────

/// Owns the context so teardown is stop-then-destroy: this `Drop` runs first,
/// then the field's own `Drop` calls `logosdelivery_destroy`.
struct Node {
    ctx: LogosDeliveryCtx,
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Err(e) = self.ctx.stop_node() {
            warn!("stop_node failed during drop: {e}");
        }
        info!("logos-delivery node stopped");
    }
}

// ── ThreadedDeliveryWrapper ─────────────────────────────────────────────────

/// Owns the embedded node. `T` is whatever the mapper passed to [`Self::start`]
/// produces; mapping runs on the callback thread, so filtering and decoding
/// happen inline. Cheap to clone — all clones share one node.
pub struct ThreadedDeliveryWrapper<T = WakuEvent> {
    node: Arc<Node>,
    inbound_rx: Option<Receiver<T>>,
}

// Manual impls so `T` carries no `Clone`/`Debug` bound at the struct level —
// `Receiver<T>` is `Clone` for every `T`.
impl<T> Clone for ThreadedDeliveryWrapper<T> {
    fn clone(&self) -> Self {
        Self {
            node: self.node.clone(),
            inbound_rx: self.inbound_rx.clone(),
        }
    }
}

impl<T> std::fmt::Debug for ThreadedDeliveryWrapper<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThreadedDeliveryWrapper")
            .field("has_inbound", &self.inbound_rx.is_some())
            .finish_non_exhaustive()
    }
}

impl<T> ThreadedDeliveryWrapper<T> {
    /// Start the embedded logos-delivery node. `map` runs on the node's event
    /// callback for every received event; return `Some(item)` to enqueue it for
    /// [`Self::inbound_queue`], or `None` to drop it. It must be non-blocking.
    pub fn start<F>(cfg: P2pConfig, map: F) -> Result<Self, DeliveryError>
    where
        T: Clone + Send + 'static,
        F: FnMut(WakuEvent) -> Option<T> + Send + 'static,
    {
        let (inbound_tx, inbound_rx) = crossbeam_channel::bounded::<T>(INBOUND_CAPACITY);

        let ctx = LogosDeliveryCtx::create(cfg.to_json(), NODE_CALL_TIMEOUT)
            .map_err(DeliveryError::StartupFailed)?;

        // Registered before starting so no event can arrive unlistened. The ctx
        // owns the closure, so the handle is unused. The mutex is because the
        // listener wants `Fn` while the mapper is `FnMut`.
        let mapper = Mutex::new(map);
        let _handle =
            ctx.add_on_message_received_listener(move |event: &MessageReceivedPayload| {
                let item = match mapper.lock() {
                    Ok(mut map) => map(WakuEvent {
                        message: event.message.clone(),
                    }),
                    Err(e) => {
                        error!("mapper mutex poisoned: {e}");
                        return;
                    }
                };
                let Some(item) = item else {
                    return;
                };
                match inbound_tx.try_send(item) {
                    Ok(()) => {}
                    Err(crossbeam_channel::TrySendError::Full(_)) => {
                        warn!("inbound queue full; dropping message")
                    }
                    Err(crossbeam_channel::TrySendError::Disconnected(_)) => {}
                }
            });

        ctx.start_node().map_err(DeliveryError::StartupFailed)?;
        info!("logos-delivery node started (preset={})", cfg.preset);

        // FIXME: stand-in for peer-connectivity detection. Should wait on
        // `add_on_connection_change_listener` until a peer is reachable, with
        // this duration as the timeout.
        thread::sleep(Duration::from_secs(3));

        Ok(Self {
            node: Arc::new(Node { ctx }),
            inbound_rx: Some(inbound_rx),
        })
    }

    /// Start delivering messages on `content_topic`. Blocks until acknowledged.
    pub fn subscribe(&self, content_topic: &str) -> Result<(), DeliveryError> {
        debug!(?content_topic, "Subscribe");
        self.node
            .ctx
            .subscribe(content_topic.to_string())
            .map(|_| ())
            .map_err(DeliveryError::SubscribeFailed)
    }

    /// Stop delivering messages on `content_topic`. Blocks until acknowledged.
    pub fn unsubscribe(&self, content_topic: &str) -> Result<(), DeliveryError> {
        debug!(?content_topic, "Unsubscribe");
        self.node
            .ctx
            .unsubscribe(content_topic.to_string())
            .map(|_| ())
            .map_err(DeliveryError::UnsubscribeFailed)
    }

    /// Publish `payload` on `content_topic`. Blocks until the node acknowledges.
    pub fn publish(&self, content_topic: &str, payload: &[u8]) -> Result<(), DeliveryError> {
        let req = SendRequest {
            content_topic: content_topic.to_string(),
            payload: BASE64.encode(payload),
            ephemeral: false,
        };

        debug!(content_topic = ?req.content_topic, payload = ?req.payload, ephemeral = ?req.ephemeral, "Publish");

        self.node
            .ctx
            .send(req)
            .map(|_| ())
            .map_err(DeliveryError::PublishFailed)
    }

    /// Take the inbound queue of mapped items. Callable once.
    pub fn inbound_queue(&mut self) -> Receiver<T> {
        self.inbound_rx
            .take()
            .expect("inbound_queue called more than once")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mapper that filters by content topic and decodes to bytes has to be
    /// accepted by `start`'s bound.
    #[test]
    fn accepts_a_filtering_mapper() {
        const CHAT_TOPIC_PREFIX: &str = "/logos-chat/1/";

        fn accepts<F>(_map: F)
        where
            F: FnMut(WakuEvent) -> Option<Vec<u8>> + Send + 'static,
        {
        }

        accepts(|event: WakuEvent| {
            let msg = event.into_received()?;
            if !msg.content_topic().starts_with(CHAT_TOPIC_PREFIX) {
                return None;
            }
            msg.into_payload()
        });
    }

    #[test]
    fn config_json_has_the_keys_the_node_expects() {
        let cfg = P2pConfig {
            preset: "logos.dev".into(),
            port: 60010,
            log_level: "ERROR".into(),
        };
        let json: serde_json::Value = serde_json::from_str(&cfg.to_json()).unwrap();

        assert_eq!(json["preset"], "logos.dev");
        assert_eq!(json["mode"], "Core");
        assert_eq!(json["logLevel"], "ERROR");
        // Both ports track `port`, so one knob keeps instances from colliding.
        assert_eq!(json["tcpPort"], 60010);
        assert_eq!(json["discv5UdpPort"], 60010);
    }

    #[test]
    fn received_message_decodes_base64_payload() {
        let msg = ReceivedMessage {
            message: WakuMessagePayload {
                payload: BASE64.encode(b"hello"),
                content_topic: "/logos-chat/1/demo/proto".into(),
                version: 0,
                timestamp: 0,
                ephemeral: false,
                meta: String::new(),
                proof: String::new(),
            },
        };

        assert_eq!(msg.content_topic(), "/logos-chat/1/demo/proto");
        assert_eq!(msg.into_payload().unwrap(), b"hello");
    }
}
