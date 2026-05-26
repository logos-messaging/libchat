/// Routes inbound transport payloads to per-topic handlers.
///
/// Transports (`DeliveryService` implementations) deliver `(delivery_address,
/// payload)` pairs into an mpsc receiver. The receive loop walks a list of
/// handlers and offers each payload to the first one whose `matches` returns
/// `true`. The chat path (`ChatClient::receive`) is the default fall-through
/// when no handler claims a topic.
///
/// Handlers own their own state and side-effects: results are surfaced via
/// channels or fields the handler controls, not through the trait. This keeps
/// the trait narrow enough for new topic-scoped services (key-package registry,
/// presence, broadcasts) to plug in without coupling to chat-specific types.
pub trait TopicHandler {
    /// Returns `true` if this handler should process `delivery_address`.
    fn matches(&self, delivery_address: &str) -> bool;

    /// Process a payload addressed to a topic this handler matched.
    fn handle(&mut self, delivery_address: &str, payload: &[u8]);
}
