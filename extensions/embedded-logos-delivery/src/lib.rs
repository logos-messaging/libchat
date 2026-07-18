//! The embedded logos-delivery transport service.
//!
//! [`EmbeddedLogosDelivery`] implements [`DeliveryService`] over an embedded
//! node driven through `waku-bindings`' [`LogosDeliveryCtx`]. The bindings own
//! the node and its event dispatch, so this crate only supplies the
//! delivery-specific mapping: one reliable channel per delivery address, the
//! content-topic naming, and payload coding.
//!
//! ## Reliable channels
//!
//! Traffic rides logos-delivery's *reliable channel* API (SDS) rather than raw
//! publish/subscribe, so the node handles acknowledgement, retransmission and
//! causal ordering. Each `delivery_address` maps to one channel, keyed by that
//! address, carried on content topic `/logos-chat/1/{delivery_address}/proto`.
//!
//! Two details of that API drive the code below:
//!
//! - Creating a channel does **not** subscribe to its content topic, and both
//!   ends of a channel must do both — the publisher included, since SDS
//!   acknowledgements travel back over that topic. So the pair is done together
//!   in `ensure_channel`, on the publish path as much as the subscribe one.
//! - A channel's shard is derived from its content topic, so the node needs
//!   autosharding. The `logos.dev` preset supplies it (cluster 2, 8 shards).
//!
//! ## Why a dedicated node thread
//!
//! Every `LogosDeliveryCtx` call is blocking: it hands a request to the node's
//! FFI thread and waits for the result callback. Issuing such a call from
//! whatever thread libchat happens to be on — in particular the thread draining
//! the inbound queue, which calls [`subscribe`](DeliveryService::subscribe)
//! while processing a received frame — wedges: the call is made downstream of
//! the node's own event dispatch and never returns.
//!
//! So this owns a single [`node_thread`] that holds the ctx and is the only
//! caller of it. [`DeliveryService`] methods just hand it a [`NodeCmd`] over a
//! channel and block on the reply, so ctx calls are serialised on one thread,
//! decoupled from both the caller and the event callback. This mirrors the
//! design the previous (hand-written FFI) transport used for the same reason.
//!
//! The native node is linked transitively via `waku-bindings`, so this crate
//! lives outside the workspace's default members; depend on it (e.g. via the
//! `logos-chat` crate) only when shipping the embedded node.

use std::collections::HashSet;
use std::fmt;
use std::sync::mpsc::{self, SyncSender};
use std::thread;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use crossbeam_channel::{Receiver, Sender};
use libchat::{AddressedEnvelope, DeliveryService};
use tracing::{debug, error, info, warn};
use waku_bindings::{ChannelSendRequest, LogosDeliveryCtx};

/// The logos-delivery network preset joined by default.
pub const DEFAULT_NETWORK_PRESET: &str = "logos.dev";

/// Default TCP port for the embedded logos-delivery node.
pub const DEFAULT_TCP_PORT: u16 = 60000;

/// The content-topic prefix carrying logos-chat traffic.
const CHAT_TOPIC_PREFIX: &str = "/logos-chat/1/";

/// The only encryption mechanism logos-delivery implements today. Despite being
/// named per channel it installs process-wide, so every channel here uses it.
const NOOP_ENCRYPTION: &str = "noop";

/// How long to wait for a node operation to come back through the FFI callback.
const NODE_TIMEOUT: Duration = Duration::from_secs(30);

/// Inbound queue depth, matching the previous wrapper's.
const INBOUND_CAPACITY: usize = 1024;

/// Outbound command queue depth.
const COMMAND_CAPACITY: usize = 256;

pub fn content_topic_for(delivery_address: &str) -> String {
    format!("{CHAT_TOPIC_PREFIX}{delivery_address}/proto")
}

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum DeliveryError {
    #[error("node startup failed: {0}")]
    StartupFailed(String),
    #[error("channel create failed: {0}")]
    ChannelCreateFailed(String),
    #[error("publish failed: {0}")]
    PublishFailed(String),
    #[error("subscribe failed: {0}")]
    SubscribeFailed(String),
    #[error("unsubscribe failed: {0}")]
    UnsubscribeFailed(String),
    #[error("node thread is gone")]
    NodeGone,
}

// ── P2pConfig ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct P2pConfig {
    pub preset: String,
    pub port: u16,
    pub log_level: String,
    /// This node's SDS participant id. Channel state is keyed by channel id and
    /// participant, so peers sharing a channel must not share this.
    pub sender_id: String,
    /// Where the node keeps its local data, SDS channel state included. The
    /// persistency layer is a process-wide singleton keyed on this path, so two
    /// nodes on one machine need distinct paths or each will read the other's
    /// causal history and drop its messages as replays.
    pub storage_path: String,
}

impl Default for P2pConfig {
    // Generate a P2pConfig that connects to the `logos.dev` network and uses a randomly assigned port.
    // Random port avoids conflicts with other services on the machine, and allows multiple instances
    // to run in parallel.
    fn default() -> Self {
        /// Default to an OS assigned port, that is available
        const DEFAULT_PORT: u16 = 0;
        Self {
            preset: DEFAULT_NETWORK_PRESET.into(),
            port: DEFAULT_PORT,
            log_level: "ERROR".into(),
            // Random per node: `logos_chat::open` already mints a fresh account
            // on every open, so a participant id that outlived the process
            // would claim continuity the identity above does not have.
            sender_id: uuid::Uuid::new_v4().to_string(),
            storage_path: "./data-logos-delivery".into(),
        }
    }
}

impl P2pConfig {
    /// The node's configuration JSON.
    ///
    /// This is the flat shape: a blob of kernel fields. logos-delivery also
    /// accepts a structured `{mode, preset, messagingOverrides, ...}` shape, but
    /// that one has no way to set a TCP port, so the flat shape is the one that
    /// fits. Both enable reliable channels.
    fn to_config_json(&self) -> String {
        // discv5UdpPort defaults to 9000 in libwaku, so a second instance with
        // a distinct --port still collides on UDP. Bind it to tcp_port so a
        // single --port knob keeps both ports distinct across instances.
        serde_json::json!({
            "logLevel": self.log_level,
            "mode": "Core",
            "preset": self.preset,
            "tcpPort": self.port,
            "discv5UdpPort": self.port,
            "local-storage-path": self.storage_path,
        })
        .to_string()
    }
}

// ── Node commands ────────────────────────────────────────────────────────────

/// A node operation to run on the serialised node thread.
enum NodeOp {
    Subscribe(String),        // delivery_address
    Publish(String, Vec<u8>), // delivery_address, payload
    Unsubscribe(String),      // delivery_address
}

struct NodeCmd {
    op: NodeOp,
    reply: SyncSender<Result<(), DeliveryError>>,
}

// ── EmbeddedLogosDelivery ──────────────────────────────────────────────────

/// logos-delivery backed delivery service. Cheap to clone — all clones share
/// the same background node.
#[derive(Clone)]
pub struct EmbeddedLogosDelivery {
    outbound: SyncSender<NodeCmd>,
    inbound: Receiver<Vec<u8>>,
    /// Kept only so [`Debug`] and callers have something to show; the node
    /// thread owns the id it actually uses.
    sender_id: String,
}

// The command/inbound channels are opaque, so a derived Debug would be noise.
impl fmt::Debug for EmbeddedLogosDelivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmbeddedLogosDelivery")
            .field("sender_id", &self.sender_id)
            .finish_non_exhaustive()
    }
}

impl EmbeddedLogosDelivery {
    /// Start the embedded logos-delivery node on its own thread. Channel
    /// payloads arrive already unwrapped from their SDS envelope, so they land
    /// on the inbound queue as the raw bytes that were published.
    pub fn start(cfg: P2pConfig) -> Result<Self, DeliveryError> {
        let sender_id = cfg.sender_id.clone();
        let (out_tx, out_rx) = mpsc::sync_channel::<NodeCmd>(COMMAND_CAPACITY);
        let (inbound_tx, inbound_rx) = crossbeam_channel::bounded::<Vec<u8>>(INBOUND_CAPACITY);
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), DeliveryError>>();

        thread::Builder::new()
            .name("logos-node".into())
            .spawn(move || node_thread(cfg, out_rx, inbound_tx, ready_tx))
            .map_err(|e| DeliveryError::StartupFailed(e.to_string()))?;

        // Block until the node has started (or failed to), so a returned handle
        // is always backed by a live node.
        ready_rx
            .recv()
            .map_err(|_| DeliveryError::StartupFailed("node thread died on startup".into()))??;

        Ok(Self {
            outbound: out_tx,
            inbound: inbound_rx,
            sender_id,
        })
    }

    /// Hand an op to the node thread and wait for its result.
    fn run(&self, op: NodeOp) -> Result<(), DeliveryError> {
        let (reply_tx, reply_rx) = mpsc::sync_channel::<Result<(), DeliveryError>>(1);
        self.outbound
            .send(NodeCmd {
                op,
                reply: reply_tx,
            })
            .map_err(|_| DeliveryError::NodeGone)?;
        reply_rx.recv().map_err(|_| DeliveryError::NodeGone)?
    }

    /// Stop delivering messages addressed to `delivery_address`, closing its
    /// channel.
    pub fn unsubscribe(&self, delivery_address: &str) -> Result<(), DeliveryError> {
        self.run(NodeOp::Unsubscribe(delivery_address.to_string()))
    }
}

impl DeliveryService for EmbeddedLogosDelivery {
    type Error = DeliveryError;

    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), DeliveryError> {
        self.run(NodeOp::Publish(envelope.delivery_address, envelope.data))
    }

    fn subscribe(&mut self, delivery_address: &str) -> Result<(), DeliveryError> {
        self.run(NodeOp::Subscribe(delivery_address.to_string()))
    }
}

// Teaching the service the inbound half makes it a full client transport, so
// callers need no wrapper newtype. The impl lives here (the crate owning the
// type) because the orphan rule bars it from the `logos-chat` crate, which
// owns neither the trait nor the type.
impl logos_generic_chat::Transport for EmbeddedLogosDelivery {
    fn inbound(&mut self) -> Receiver<Vec<u8>> {
        self.inbound.clone()
    }
}

// ── Node thread ──────────────────────────────────────────────────────────────

/// Owns the node and is the sole caller of its (blocking) ctx methods. Runs
/// until every [`EmbeddedLogosDelivery`] clone is dropped and the command
/// channel closes, then drops the ctx (whose `Drop` stops the node).
fn node_thread(
    cfg: P2pConfig,
    out_rx: mpsc::Receiver<NodeCmd>,
    inbound_tx: Sender<Vec<u8>>,
    ready_tx: mpsc::Sender<Result<(), DeliveryError>>,
) {
    let ctx = match LogosDeliveryCtx::create(cfg.to_config_json(), NODE_TIMEOUT) {
        Ok(ctx) => ctx,
        Err(e) => {
            let _ = ready_tx.send(Err(DeliveryError::StartupFailed(e)));
            return;
        }
    };

    // Registered before the node starts, so there is no window where the node
    // is live but the queue is not yet fed. The callback only enqueues — it
    // never calls back into the ctx, so it cannot re-enter the node.
    ctx.add_on_channel_message_received_listener(move |event| {
        let payload = match BASE64.decode(&event.payload) {
            Ok(payload) => payload,
            Err(e) => {
                error!(channel = %event.channel_id, "undecodable channel payload: {e}");
                return;
            }
        };
        debug!(channel = %event.channel_id, len = payload.len(), "Received");
        if inbound_tx.try_send(payload).is_err() {
            warn!(channel = %event.channel_id, "inbound queue full, dropping message");
        }
    });

    // Surfacing send failures matters more here than with raw publish: a channel
    // send is acknowledged asynchronously, so this is the only place a delivery
    // failure is reported.
    ctx.add_on_channel_message_error_listener(|event| {
        error!(
            channel = %event.channel_id,
            request = %event.request_id,
            "channel send failed: {}", event.error
        );
    });

    if let Err(e) = ctx.start_node() {
        let _ = ready_tx.send(Err(DeliveryError::StartupFailed(e)));
        return;
    }
    info!("logos-delivery node started (preset={})", cfg.preset);

    // FIXME: This unconditional sleep is a stand-in for proper peer-connectivity
    // detection: proceed once at least one peer is reachable, falling back to a
    // configurable timeout. The bindings expose `add_on_connection_change_listener`,
    // so the event this needs exists — wiring it up is left to a focused change.
    thread::sleep(Duration::from_secs(3));

    if ready_tx.send(Ok(())).is_err() {
        // The starter gave up waiting; nothing holds a handle, so there is
        // nothing to serve.
        return;
    }

    // Channels already opened on the node, so create/subscribe is issued once
    // per address. Owned by this thread alone — no lock needed.
    let mut open: HashSet<String> = HashSet::new();

    while let Ok(cmd) = out_rx.recv() {
        let result = match cmd.op {
            NodeOp::Subscribe(addr) => ensure_channel(&ctx, &mut open, &cfg.sender_id, &addr),
            NodeOp::Publish(addr, data) => ensure_channel(&ctx, &mut open, &cfg.sender_id, &addr)
                .and_then(|()| publish(&ctx, &addr, &data)),
            NodeOp::Unsubscribe(addr) => unsubscribe(&ctx, &mut open, &addr),
        };
        // A disconnected reply just means the caller stopped waiting.
        let _ = cmd.reply.try_send(result);
    }

    info!("logos-node command loop finished");
}

/// Open the channel for `delivery_address`, and subscribe to the content topic
/// carrying it, unless that is already done.
///
/// Both halves are needed on **either** end of a channel, sender included:
/// creating a channel does not subscribe, ingress arrives through the messaging
/// layer, and SDS acknowledgements come back over that same topic — so a
/// publisher that skips the subscribe sends into a channel whose replies it can
/// never hear, and delivery quietly fails.
fn ensure_channel(
    ctx: &LogosDeliveryCtx,
    open: &mut HashSet<String>,
    sender_id: &str,
    delivery_address: &str,
) -> Result<(), DeliveryError> {
    if open.contains(delivery_address) {
        return Ok(());
    }

    ctx.channel_create(
        delivery_address.to_string(),
        content_topic_for(delivery_address),
        sender_id.to_string(),
        NOOP_ENCRYPTION.to_string(),
    )
    .map_err(DeliveryError::ChannelCreateFailed)?;

    ctx.subscribe(content_topic_for(delivery_address))
        .map_err(DeliveryError::SubscribeFailed)?;

    debug!(channel = delivery_address, "Channel opened");
    open.insert(delivery_address.to_string());
    Ok(())
}

fn publish(
    ctx: &LogosDeliveryCtx,
    delivery_address: &str,
    data: &[u8],
) -> Result<(), DeliveryError> {
    debug!(
        topic = content_topic_for(delivery_address),
        len = data.len(),
        "Publish"
    );
    ctx.channel_send(
        delivery_address.to_string(),
        ChannelSendRequest {
            payload: BASE64.encode(data),
            ephemeral: false,
        },
    )
    .map(|_request_id| ())
    .map_err(DeliveryError::PublishFailed)
}

fn unsubscribe(
    ctx: &LogosDeliveryCtx,
    open: &mut HashSet<String>,
    delivery_address: &str,
) -> Result<(), DeliveryError> {
    ctx.unsubscribe(content_topic_for(delivery_address))
        .map_err(DeliveryError::UnsubscribeFailed)?;

    // Closing drops the channel from the node's manager; its SDS state is
    // persisted, so a later subscribe resumes rather than starts over.
    if open.remove(delivery_address) {
        ctx.channel_close(delivery_address.to_string())
            .map_err(DeliveryError::UnsubscribeFailed)?;
    }
    Ok(())
}
