use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::Sender;
use libchat::{ConversationId, WakeupService};

#[derive(Debug, Eq, PartialEq)]
struct WakeupRecord {
    expiry: Instant,
    convo_id: ConversationId,
}

impl Ord for WakeupRecord {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.expiry.cmp(&other.expiry)
    }
}

impl PartialOrd for WakeupRecord {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Sent to the wakeup queue when a previously registered timer expires.
#[derive(Debug, Clone)]
pub struct WakeupEvent {
    pub convo_id: ConversationId,
}

struct Shared {
    pending: Mutex<BinaryHeap<Reverse<WakeupRecord>>>,
    condvar: Condvar,
    running: AtomicBool,
}

/// A [`WakeupService`] backed by a background thread that sleeps until the
/// nearest pending deadline, then emits a [`WakeupEvent`] on `events`.
pub struct ThreadedWakeupService {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl fmt::Debug for ThreadedWakeupService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreadedWakeupService").finish()
    }
}

impl ThreadedWakeupService {
    pub fn new(events: Sender<WakeupEvent>) -> Self {
        let shared = Arc::new(Shared {
            pending: Mutex::new(BinaryHeap::new()),
            condvar: Condvar::new(),
            running: AtomicBool::new(true),
        });

        let thread = thread::spawn({
            let shared = Arc::clone(&shared);
            move || run(shared, events)
        });

        Self {
            shared,
            thread: Some(thread),
        }
    }
}

impl WakeupService for ThreadedWakeupService {
    fn wakeup_in(&mut self, duration: Duration, convo_id: ConversationId) {
        let mut pending = self.shared.pending.lock().unwrap();
        pending.push(Reverse(WakeupRecord {
            expiry: Instant::now() + duration,
            convo_id,
        }));
        // The worker may be sleeping until a later deadline; wake it so it
        // can recompute the time until the new nearest deadline.
        self.shared.condvar.notify_one();
    }
}

impl Drop for ThreadedWakeupService {
    fn drop(&mut self) {
        self.shared.running.store(false, Ordering::SeqCst);
        self.shared.condvar.notify_one();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Background loop: sleep until the nearest deadline (or forever if the heap
/// is empty), then drain and emit any expired records.
fn run(shared: Arc<Shared>, events: Sender<WakeupEvent>) {
    loop {
        let mut pending = shared.pending.lock().unwrap();

        if !shared.running.load(Ordering::SeqCst) {
            return;
        }

        let Some(Reverse(next)) = pending.peek() else {
            // Nothing scheduled: wait until a registration or shutdown wakes us.
            drop(shared.condvar.wait(pending).unwrap());
            continue;
        };

        let now = Instant::now();
        if next.expiry > now {
            let timeout = next.expiry - now;
            drop(shared.condvar.wait_timeout(pending, timeout).unwrap());
            continue;
        }

        let Reverse(record) = pending.pop().unwrap();
        drop(pending);

        if events
            .send(WakeupEvent {
                convo_id: record.convo_id,
            })
            .is_err()
        {
            return;
        }
    }
}
