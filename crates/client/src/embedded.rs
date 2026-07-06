//! The Logos client on the embedded logos-delivery transport.
//!
//! The node links the native `liblogosdelivery` (via the
//! `embedded-logos-delivery` crate), so this whole module sits behind the
//! `embedded-logos-delivery` cargo feature, which just switches on that
//! optional dependency. The transport-generic Logos stack it builds on lives
//! in [`crate::logos`] and compiles unconditionally.

use crossbeam_channel::Receiver;
use embedded_logos_delivery::{EmbeddedLogosDelivery, P2pConfig};

use crate::client::Transport;
use crate::errors::ClientError;
use crate::event::Event;
use crate::logos::{LogosChatClient, LogosConfig};

// The embedded service implements `DeliveryService` in its own crate; teaching
// it the inbound half here (in the crate that owns `Transport`) makes it a
// full transport, so callers need no wrapper newtype.
impl Transport for EmbeddedLogosDelivery {
    fn inbound(&mut self) -> Receiver<Vec<u8>> {
        self.inbound_queue()
    }
}

/// The Logos client running an embedded logos-delivery node as its transport.
/// Open one with [`open`](Self::open).
pub type EmbeddedLogosClient = LogosChatClient<EmbeddedLogosDelivery>;

impl EmbeddedLogosClient {
    /// Open a client on the Logos stack per `config`, starting an embedded
    /// logos-delivery node per `p2p_config` as its transport. A convenience
    /// over [`open_with_transport`](Self::open_with_transport); the transport
    /// is already named by the [`EmbeddedLogosClient`] alias callers reach
    /// this through.
    pub fn open(
        config: LogosConfig,
        p2p_config: P2pConfig,
    ) -> Result<(Self, Receiver<Event>), ClientError> {
        let transport = EmbeddedLogosDelivery::start(p2p_config)
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        Self::open_with_transport(config, transport)
    }
}
