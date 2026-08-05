//! Drop-in replacement for `extensions/logos-delivery-rust`, built on the
//! upstream `waku-bindings` generated FFI layer instead of a hand-written one.
//!
//! The public API is deliberately identical to that crate's — same types, same
//! method signatures, same semantics — so `embedded-logos-delivery` compiles
//! against either without a source change. See this crate's `Cargo.toml` for
//! the one-line swap.
//!
//! ## What moved
//!
//! `sys.rs` and `wrapper.rs` are gone. The raw `extern "C"` declarations, the
//! callback trampoline, the `Box::into_raw` dance that kept one-shot closures
//! alive across the async FFI boundary, and the `_event_cb` field-drop-order
//! trick are all supplied by `LogosDeliveryCtx`, which owns its listener
//! closures in an internal map for exactly that reason.
//!
//! The dedicated node thread and its command loop are gone too.
//! `LogosDeliveryCtx` is `Send + Sync` — every call is funnelled through
//! nim-ffi's single dispatch thread, which serialises them internally — so
//! `publish`/`subscribe`/`unsubscribe` can be invoked directly from any
//! thread. The wrapper is now an `Arc` handle plus the inbound queue.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use crossbeam_channel::Receiver;
use tracing::{debug, error, info, warn};
use waku_bindings::{LogosDeliveryCtx, MessageReceivedPayload, SendRequest, WakuMessagePayload};

/// Applied to node creation and to every subsequent call: `LogosDeliveryCtx`
/// stores the duration handed to `create` and reuses it for each request.
const NODE_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Inbound queue depth. Matches the hand-written crate.
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
    // Generate a P2pConfig that connects to the `logos.dev` network and uses a randomly assigned port.
    // Random port avoids conflicts with other services on the machine, and allows multiple instances
    // to run in parallel.
    fn default() -> Self {
        /// The logos-delivery network preset joined by default.
        const DEFAULT_NETWORK_PRESET: &str = "logos.dev";
        /// Default to an OS assigned port, that is available
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
    ///
    /// `create` still takes an opaque JSON string, so these keys carry over
    /// from the hand-written crate untouched — the bindings' own
    /// `WakuNodeConfig` (which has no `preset`/`mode`) is not in the way.
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
///
/// Retained for API compatibility. The hand-written crate parsed a raw JSON
/// envelope carrying any `eventType` and needed [`Self::into_received`] to
/// narrow it; here the typed listener is already scoped to that one event, so
/// the narrowing always succeeds. Keeping the method means the mapper closures
/// callers already wrote still compile.
#[derive(Debug, Clone)]
pub struct WakuEvent {
    message: WakuMessagePayload,
}

impl WakuEvent {
    /// The received message. Always `Some` — see the type docs.
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

    /// Decode the payload to raw bytes.
    ///
    /// The generated layer types the payload as a base64 `String`, so unlike
    /// the hand-written crate there is no second, byte-array wire form to
    /// accommodate.
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

/// Owns the embedded node. Generic over the inbound item type `T`: a
/// caller-supplied mapper turns each [`WakuEvent`] into an `Option<T>` on the
/// callback thread, so filtering and decoding happen inline with no relay
/// thread. Cheap to clone — all clones share the same node.
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

        // Register before starting, so there is no window where the node is
        // live but the listener is not yet attached. The ctx owns the closure
        // from here on, so the handle is not needed.
        //
        // The listener wants `Fn + Send + Sync`; the caller's mapper is `FnMut`,
        // hence the mutex. It is only ever contended if the node dispatches
        // events from more than one thread.
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

        // FIXME: This unconditional sleep is a stand-in for proper
        // peer-connectivity detection. The right approach is to listen for a
        // `peer_connected` (or equivalent status-change) event from the node
        // callback and only proceed once at least one peer is reachable,
        // falling back to a configurable timeout.
        //
        // The generated layer now surfaces exactly that:
        // `add_on_connection_change_listener` (peer id + peer event) and
        // `add_on_connection_status_change_listener`. Replacing this sleep is
        // a follow-up kept out of the swap so the two crates stay
        // behaviourally identical.
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

    /// Compile-level proof of the drop-in claim: this is
    /// `EmbeddedLogosDelivery::start`'s mapper verbatim. If the swap were to
    /// break `embedded-logos-delivery`, it would fail to compile here first.
    #[test]
    fn mapper_closure_matches_embedded_logos_delivery() {
        const CHAT_TOPIC_PREFIX: &str = "/logos-chat/1/";

        fn takes_the_same_mapper<F>(_map: F)
        where
            F: FnMut(WakuEvent) -> Option<Vec<u8>> + Send + 'static,
        {
        }

        takes_the_same_mapper(|event: WakuEvent| {
            let msg = event.into_received()?;
            if !msg.content_topic().starts_with(CHAT_TOPIC_PREFIX) {
                return None;
            }
            msg.into_payload()
        });
    }

    #[test]
    fn config_json_carries_the_hand_written_keys() {
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
