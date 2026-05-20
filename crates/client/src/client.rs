use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use libchat::{
    ChatError, ChatStorage, Context, ConversationIdOwned, DeliveryService, Event, Introduction,
    StorageConfig,
};

use components::EphemeralRegistry;

use crate::errors::ClientError;

type ChatContext<D> = Context<D, EphemeralRegistry, ChatStorage>;

const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// High-level chat client. Construction returns the handle together with a
/// `Receiver<Event>` for inbound observation.
pub struct ChatClient<D: DeliveryService> {
    ctx: Arc<Mutex<ChatContext<D>>>,
    shutdown: Arc<AtomicBool>,
    translator: Option<JoinHandle<()>>,
}

impl<D: DeliveryService + 'static> ChatClient<D> {
    /// In-memory, ephemeral client. Identity is lost on drop.
    pub fn new(name: impl Into<String>, delivery: D) -> (Self, mpsc::Receiver<Event>) {
        let registry = EphemeralRegistry::new();
        let store = ChatStorage::in_memory();
        let ctx = Context::new_with_name(name, delivery, registry, store).unwrap();
        Self::wrap(ctx)
    }

    /// Persistent client backed by `config`. Identity is loaded if present,
    /// otherwise created and saved.
    pub fn open(
        name: impl Into<String>,
        config: StorageConfig,
        delivery: D,
    ) -> Result<(Self, mpsc::Receiver<Event>), ClientError<D::Error>> {
        let store = ChatStorage::new(config).map_err(ChatError::from)?;
        let registry = EphemeralRegistry::new();
        let ctx = Context::new_from_store(name, delivery, registry, store)?;
        Ok(Self::wrap(ctx))
    }

    pub fn installation_name(&self) -> String {
        self.ctx.lock().unwrap().installation_name().to_string()
    }

    pub fn create_intro_bundle(&mut self) -> Result<Vec<u8>, ClientError<D::Error>> {
        self.ctx
            .lock()
            .unwrap()
            .create_intro_bundle()
            .map_err(Into::into)
    }

    pub fn create_conversation(
        &mut self,
        intro_bundle: &[u8],
        initial_content: &[u8],
    ) -> Result<(ConversationIdOwned, Vec<Event>), ClientError<D::Error>> {
        let intro = Introduction::try_from(intro_bundle)?;
        self.ctx
            .lock()
            .unwrap()
            .create_private_convo(&intro, initial_content)
            .map_err(Into::into)
    }

    pub fn list_conversations(&self) -> Result<Vec<ConversationIdOwned>, ClientError<D::Error>> {
        self.ctx
            .lock()
            .unwrap()
            .list_conversations()
            .map_err(Into::into)
    }

    pub fn send_message(
        &mut self,
        convo_id: &ConversationIdOwned,
        content: &[u8],
    ) -> Result<Vec<Event>, ClientError<D::Error>> {
        self.ctx
            .lock()
            .unwrap()
            .send_content(convo_id.as_ref(), content)
            .map_err(Into::into)
    }

    fn wrap(ctx: ChatContext<D>) -> (Self, mpsc::Receiver<Event>) {
        let delivery = ctx.delivery_arc();
        let ctx = Arc::new(Mutex::new(ctx));
        let (event_tx, event_rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let translator_ctx = Arc::clone(&ctx);
        let translator_shutdown = Arc::clone(&shutdown);
        let translator = thread::spawn(move || {
            translator_loop(delivery, translator_ctx, event_tx, translator_shutdown)
        });
        (
            Self {
                ctx,
                shutdown,
                translator: Some(translator),
            },
            event_rx,
        )
    }
}

impl<D: DeliveryService> Drop for ChatClient<D> {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.translator.take() {
            // Best-effort: a panicked translator should not poison Drop.
            let _ = handle.join();
        }
    }
}

fn translator_loop<D: DeliveryService + 'static>(
    delivery: Arc<D>,
    ctx: Arc<Mutex<ChatContext<D>>>,
    event_tx: mpsc::Sender<Event>,
    shutdown: Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Acquire) {
        let batch = delivery.pull();
        if batch.is_empty() {
            thread::sleep(IDLE_POLL_INTERVAL);
            continue;
        }
        for bytes in batch {
            let events = match ctx.lock().unwrap().handle_payload(&bytes) {
                Ok(events) => events,
                Err(e) => {
                    tracing::warn!("handle_payload error: {e:?}");
                    continue;
                }
            };
            for event in events {
                if event_tx.send(event).is_err() {
                    tracing::info!("translator exiting: event receiver dropped");
                    return;
                }
            }
        }
    }
}
