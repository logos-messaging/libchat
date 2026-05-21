//! End-to-end test for causal-history gap detection in group conversation.
//!
//! Saro and Raya share a group. Saro sends three messages; Raya never
//! receives the second one. The third message's causal history references
//! the missing second message, so Raya must detect and report the gap.

use std::ops::{Deref, DerefMut};

use components::{EphemeralRegistry, LocalBroadcaster, MemStore};
use libchat::{Context, MissingMessage};

struct Client {
    inner: Context<LocalBroadcaster, EphemeralRegistry, MemStore>,
}

impl Client {
    fn init(ctx: Context<LocalBroadcaster, EphemeralRegistry, MemStore>) -> Self {
        Client { inner: ctx }
    }

    /// Poll every pending payload and feed it to the protocol.
    fn process_messages(&mut self) {
        let messages: Vec<_> = {
            let mut ds = self.inner.ds();
            std::iter::from_fn(|| ds.poll()).collect()
        };
        for data in messages {
            self.inner.handle_payload(&data).unwrap();
        }
    }

    /// Poll every pending payload and discard it — simulates messages that
    /// never reach this client.
    fn drop_pending_messages(&mut self) {
        let mut ds = self.inner.ds();
        while ds.poll().is_some() {}
    }
}

impl Deref for Client {
    type Target = Context<LocalBroadcaster, EphemeralRegistry, MemStore>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Client {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[test]
fn missing_group_message_is_detected() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let saro_ctx =
        Context::new_with_name("saro", ds.new_consumer(), rs.clone(), MemStore::new()).unwrap();

    let raya_ctx = Context::new_with_name("raya", ds.clone(), rs.clone(), MemStore::new()).unwrap();

    let mut saro = Client::init(saro_ctx);
    let mut raya = Client::init(raya_ctx);

    // Saro creates a group with Raya.
    let raya_id = raya.account_id().clone();
    let convo_id = saro
        .create_group_convo(&[&raya_id])
        .unwrap()
        .id()
        .to_string();

    // Raya joins (processes the Welcome + commit).
    raya.process_messages();

    // M1 is delivered normally.
    saro.get_convo(convo_id.as_str())
        .unwrap()
        .send_content(b"first")
        .unwrap();
    raya.process_messages();
    assert!(
        raya.take_missing_messages().is_empty(),
        "no gap expected while every message is delivered"
    );

    // M2 is published but never reaches Raya.
    saro.get_convo(convo_id.as_str())
        .unwrap()
        .send_content(b"second")
        .unwrap();
    raya.drop_pending_messages();

    // M3 is delivered; its causal history references the missing M2.
    saro.get_convo(convo_id.as_str())
        .unwrap()
        .send_content(b"third")
        .unwrap();
    raya.process_messages();

    let missing: Vec<MissingMessage> = raya.take_missing_messages();
    assert_eq!(missing.len(), 1, "exactly one message should be missing");
    assert_eq!(missing[0].conversation_id, convo_id);
    assert!(
        !missing[0].message_id.is_empty(),
        "the missing message must be identified"
    );

    // Draining clears the report; a resolved gap is not surfaced again.
    assert!(raya.take_missing_messages().is_empty());
}
