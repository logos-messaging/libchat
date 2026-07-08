use crate::{AddressedEnvelope, DeliveryService, Transport};
use crossbeam_channel::{Receiver, Sender, unbounded};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

type Message = Vec<u8>;

/// Shared in-process message bus. Cheap to clone — all clones share one routing
/// table. On `publish`, a message is fanned out to every endpoint subscribed to
/// its delivery address.
#[derive(Clone, Default, Debug)]
pub struct MessageBus {
    routes: Arc<Mutex<HashMap<String, Vec<Sender<Message>>>>>,
}

impl MessageBus {
    fn register(&self, address: &str, sender: Sender<Message>) {
        let mut routes = self.routes.lock().unwrap();
        let senders = routes.entry(address.to_string()).or_default();
        // Idempotent per endpoint: the core re-subscribes an address whenever it
        // rebuilds a conversation, so skip senders already registered for it —
        // otherwise each payload reaches that endpoint more than once.
        if senders.iter().any(|s| s.same_channel(&sender)) {
            return;
        }
        senders.push(sender);
    }

    fn publish(&self, address: &str, data: Message) {
        if let Some(senders) = self.routes.lock().unwrap().get_mut(address) {
            // Prune endpoints whose receiver was dropped: a disconnected endpoint
            // is harmless, but keeping its sender would leak it in `routes`.
            senders.retain(|tx| tx.send(data.clone()).is_ok());
        }
    }
}

/// One client's endpoint onto a shared [`MessageBus`].
///
/// `publish` fans the message out through the bus; `subscribe` registers this
/// endpoint's inbound sender for an address, so subsequent publishes to it are
/// delivered. The client obtains the inbound stream via [`Transport::inbound`].
#[derive(Debug)]
pub struct InProcessDelivery {
    bus: MessageBus,
    inbound_tx: Sender<Message>,
    inbound_rx: Option<Receiver<Message>>,
}

impl InProcessDelivery {
    /// Create an endpoint on `bus`.
    pub fn new(bus: MessageBus) -> Self {
        let (tx, rx) = unbounded();
        Self {
            bus,
            inbound_tx: tx,
            inbound_rx: Some(rx),
        }
    }
}

impl DeliveryService for InProcessDelivery {
    type Error = Infallible;

    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), Infallible> {
        self.bus.publish(&envelope.delivery_address, envelope.data);
        Ok(())
    }

    fn subscribe(&mut self, delivery_address: &str) -> Result<(), Self::Error> {
        self.bus.register(delivery_address, self.inbound_tx.clone());
        Ok(())
    }
}

impl Transport for InProcessDelivery {
    fn inbound(&mut self) -> Receiver<Vec<u8>> {
        self.inbound_rx
            .take()
            .expect("InProcessDelivery::inbound called more than once")
    }
}
