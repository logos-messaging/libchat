use crate::{AddressedEnvelope, DeliveryService};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, RwLock};

type Message = Vec<u8>;

/// Shared in-process message bus. Cheap to clone — all clones share the same log.
///
/// Messages are stored in an append-only log per delivery address. Readers hold
/// independent [`Cursor`]s and advance their position without consuming messages,
/// so multiple consumers on the same address each see every message.
#[derive(Clone, Default)]
pub struct MessageBus {
    log: Arc<RwLock<HashMap<String, Vec<Message>>>>,
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
        let pos = self.log.read().unwrap().get(address).map_or(0, |v| v.len());
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
        self.log.read().unwrap().get(address)?.get(pos).cloned()
    }

    fn push(&self, address: String, data: Message) {
        self.log
            .write()
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
/// clients can share one logical delivery service. Construct with a
/// [`MessageBus`] and use [`cursor`](InProcessDelivery::cursor) /
/// [`cursor_at_tail`](InProcessDelivery::cursor_at_tail) to read messages.
#[derive(Clone, Default)]
pub struct InProcessDelivery(MessageBus);

impl InProcessDelivery {
    /// Create a delivery service backed by `bus`.
    pub fn new(bus: MessageBus) -> Self {
        Self(bus)
    }

    /// Returns a cursor positioned at the beginning of `address`.
    pub fn cursor(&self, address: &str) -> Cursor {
        self.0.cursor(address)
    }

    /// Returns a cursor positioned at the current tail of `address`.
    /// The cursor will only see messages delivered after this call.
    pub fn cursor_at_tail(&self, address: &str) -> Cursor {
        self.0.cursor_at_tail(address)
    }
}

impl DeliveryService for InProcessDelivery {
    type Error = Infallible;

    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), Infallible> {
        self.0.push(envelope.delivery_address, envelope.data);
        Ok(())
    }
}
