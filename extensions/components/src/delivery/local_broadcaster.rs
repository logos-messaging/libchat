use std::{
    collections::{HashSet, VecDeque},
    hash::{DefaultHasher, Hash, Hasher},
    sync::{Arc, Mutex},
};

use libchat::{AddressedEnvelope, DeliveryService};

#[derive(Debug, Default)]
struct SharedStore {
    /// Append-only log of every published envelope.
    messages: VecDeque<AddressedEnvelope>,
}

#[derive(Clone, Debug, Default)]
struct ConsumerState {
    /// Position in the shared log this consumer has scanned up to.
    cursor: usize,
    /// Addresses this consumer is interested in.
    subscriptions: HashSet<String>,
    /// IDs of envelopes this consumer itself published — used to filter them
    /// out when scanning the log (a consumer doesn't receive its own output).
    outbound_msgs: HashSet<u64>,
}

/// `DeliveryService` for tests and local examples.
///
/// Each clone is an independent consumer (own cursor, subscriptions, and
/// outbound filter) over a shared in-memory log.
#[derive(Debug)]
pub struct LocalBroadcaster {
    shared: Arc<Mutex<SharedStore>>,
    state: Mutex<ConsumerState>,
}

impl LocalBroadcaster {
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Mutex::new(SharedStore::default())),
            state: Mutex::new(ConsumerState::default()),
        }
    }

    /// Returns a new consumer that shares the same underlying log but starts
    /// at the current tail — historical messages are skipped.
    pub fn new_consumer(&self) -> Self {
        let cursor = self.shared.lock().unwrap().messages.len();
        Self {
            shared: Arc::clone(&self.shared),
            state: Mutex::new(ConsumerState {
                cursor,
                ..ConsumerState::default()
            }),
        }
    }

    fn msg_id(msg: &AddressedEnvelope) -> u64 {
        let mut hasher = DefaultHasher::new();
        msg.data.as_slice().hash(&mut hasher);
        hasher.finish()
    }
}

impl Default for LocalBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for LocalBroadcaster {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            state: Mutex::new(self.state.lock().unwrap().clone()),
        }
    }
}

impl DeliveryService for LocalBroadcaster {
    type Error = String;

    fn publish(&self, envelope: AddressedEnvelope) -> Result<(), Self::Error> {
        let id = Self::msg_id(&envelope);
        self.state.lock().unwrap().outbound_msgs.insert(id);
        self.shared.lock().unwrap().messages.push_back(envelope);
        Ok(())
    }

    fn subscribe(&self, delivery_address: &str) -> Result<(), Self::Error> {
        self.state
            .lock()
            .unwrap()
            .subscriptions
            .insert(delivery_address.to_string());
        Ok(())
    }

    fn pull(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let shared = self.shared.lock().unwrap();
        let mut state = self.state.lock().unwrap();
        while state.cursor < shared.messages.len() {
            let ae = &shared.messages[state.cursor];
            state.cursor += 1;
            if state.subscriptions.contains(&ae.delivery_address)
                && !state.outbound_msgs.contains(&Self::msg_id(ae))
            {
                out.push(ae.data.clone());
            }
        }
        out
    }
}
