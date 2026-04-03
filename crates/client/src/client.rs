use chat_sqlite::StorageConfig;
use libchat::ChatError;
use libchat::ChatStorage;
use libchat::Context;

pub struct ChatClient {
    ctx: Context<ChatStorage>,
}

impl ChatClient {
    pub fn new(name: impl Into<String>) -> Self {
        let store =
            ChatStorage::new(StorageConfig::InMemory).expect("in-memory storage should not fail");
        Self {
            ctx: Context::new_with_name(name, store),
        }
    }

    pub fn create_bundle(&mut self) -> Result<Vec<u8>, ChatError> {
        self.ctx.create_intro_bundle()
    }
}
