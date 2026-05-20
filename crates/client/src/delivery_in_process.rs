use crate::{AddressedEnvelope, DeliveryService};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

type Message = Vec<u8>;

/// Shared in-process message bus. Cheap to clone — all clones share the same log.
///
/// Messages are stored in an append-only log per delivery address. Readers hold
/// independent [`Cursor`]s and advance their position without consuming messages,
/// so multiple consumers on the same address each see every message.
#[derive(Clone, Default, Debug)]
pub struct MessageBus {
    log: Arc<Mutex<HashMap<String, Vec<Message>>>>,
}

impl MessageBus {
    /// Returns a cursor positioned at the beginning of `address`.
    /// The cursor will see all messages — past and future.
    pub fn cursor(&self, address: &str) -> Cursor {
        Cursor {
            bus: self.clone(),
            address: address.to_string(),
            pos: 0,
        }
    }

    /// Returns a cursor positioned at the current tail of `address`.
    /// The cursor will only see messages delivered after this call.
    pub fn cursor_at_tail(&self, address: &str) -> Cursor {
        let pos = self.log.lock().unwrap().get(address).map_or(0, |v| v.len());
        Cursor {
            bus: self.clone(),
            address: address.to_string(),
            pos,
        }
    }

    fn get(&self, address: &str, pos: usize) -> Option<Message> {
        // Unwrap produces a panic when the lock is poisoned.
        // It would most likely indicate log corruption (e.g. incomplete write from another thread),
        // so panic propagation seems appropriate.
        self.log.lock().unwrap().get(address)?.get(pos).cloned()
    }

    fn push(&self, address: String, data: Message) {
        self.log
            .lock()
            .unwrap()
            .entry(address)
            .or_default()
            .push(data);
    }
}

/// Per-consumer read cursor into a [`MessageBus`] address slot.
///
/// Reads are non-destructive: the underlying log is never modified.
/// Multiple cursors on the same address each advance independently.
pub struct Cursor {
    bus: MessageBus,
    address: String,
    pos: usize,
}

impl Iterator for Cursor {
    type Item = Message;

    fn next(&mut self) -> Option<Message> {
        let msg = self.bus.get(&self.address, self.pos)?;
        self.pos += 1;
        Some(msg)
    }
}

/// In-process delivery service backed by a [`MessageBus`].
///
/// Cheap to clone — all clones share the same underlying bus, so multiple
/// clients can share one logical delivery service. Each clone has its own
/// per-address cursor for [`DeliveryService::pull`]; tests that prefer to
/// pull directly can use [`cursor`](InProcessDelivery::cursor) /
/// [`cursor_at_tail`](InProcessDelivery::cursor_at_tail) instead.
#[derive(Default, Debug)]
pub struct InProcessDelivery {
    bus: MessageBus,
    state: Mutex<DeliveryState>,
}

#[derive(Default, Debug, Clone)]
struct DeliveryState {
    cursors: HashMap<String, usize>,
}

impl InProcessDelivery {
    /// Create a delivery service backed by `bus`.
    pub fn new(bus: MessageBus) -> Self {
        Self {
            bus,
            state: Mutex::new(DeliveryState::default()),
        }
    }

    pub fn cursor(&self, address: &str) -> Cursor {
        self.bus.cursor(address)
    }

    pub fn cursor_at_tail(&self, address: &str) -> Cursor {
        self.bus.cursor_at_tail(address)
    }
}

impl Clone for InProcessDelivery {
    fn clone(&self) -> Self {
        Self {
            bus: self.bus.clone(),
            state: Mutex::new(self.state.lock().unwrap().clone()),
        }
    }
}

impl DeliveryService for InProcessDelivery {
    type Error = Infallible;

    fn publish(&self, envelope: AddressedEnvelope) -> Result<(), Infallible> {
        self.bus.push(envelope.delivery_address, envelope.data);
        Ok(())
    }

    fn subscribe(&self, delivery_address: &str) -> Result<(), Self::Error> {
        // Initialise the cursor at the current tail so the subscriber only
        // sees subsequent messages on this address.
        let pos = self
            .bus
            .log
            .lock()
            .unwrap()
            .get(delivery_address)
            .map_or(0, |v| v.len());
        self.state
            .lock()
            .unwrap()
            .cursors
            .entry(delivery_address.to_string())
            .or_insert(pos);
        Ok(())
    }

    fn pull(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let log = self.bus.log.lock().unwrap();
        let mut state = self.state.lock().unwrap();
        for (addr, cursor) in state.cursors.iter_mut() {
            if let Some(messages) = log.get(addr) {
                while *cursor < messages.len() {
                    out.push(messages[*cursor].clone());
                    *cursor += 1;
                }
            }
        }
        out
    }
}
