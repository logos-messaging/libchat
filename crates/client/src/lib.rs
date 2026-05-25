mod client;
mod delivery_in_process;
mod errors;
mod event;

pub use client::ChatClient;
pub use delivery_in_process::{Cursor, InProcessDelivery, MessageBus};
pub use errors::ClientError;
pub use event::{ConversationClass, Event};

// Re-export types callers need to interact with ChatClient.
pub use libchat::{AddressedEnvelope, ConversationIdOwned, DeliveryService, StorageConfig};
