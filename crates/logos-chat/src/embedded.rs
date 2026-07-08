//! The Logos client on the embedded logos-delivery transport.
//!
//! The node links the native `liblogosdelivery` (via the
//! `embedded-logos-delivery` crate), so this crate lives outside the
//! workspace's default members. The transport-generic Logos stack it builds
//! on lives in [`crate::logos`].

use crossbeam_channel::Receiver;
use embedded_logos_delivery::{EmbeddedLogosDelivery, P2pConfig};
use logos_generic_chat::{ClientError, Event};

use crate::logos::{LogosChatClientInternal, LogosConfig};

/// The Logos client running an embedded logos-delivery node as its transport.
/// Open one with [`LogosConfig::open`].
pub type LogosChatClient = LogosChatClientInternal<EmbeddedLogosDelivery>;

impl LogosConfig {
    /// Open a client on the Logos stack per this config, starting an embedded
    /// logos-delivery node per `p2p_config` as its transport. A convenience
    /// over [`open_with_transport`](Self::open_with_transport) that commits
    /// to the [`LogosChatClient`] transport.
    pub fn open(
        self,
        p2p_config: P2pConfig,
    ) -> Result<(LogosChatClient, Receiver<Event>), ClientError> {
        let transport = EmbeddedLogosDelivery::start(p2p_config)
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        self.open_with_transport(transport)
    }
}
