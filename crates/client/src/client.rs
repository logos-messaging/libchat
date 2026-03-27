use libchat::ChatError;
use libchat::Context;

pub struct ChatClient {
    ctx: Context,
}

impl ChatClient {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            ctx: Context::new_with_name(name),
        }
    }

    pub fn create_bundle(&mut self) -> Result<Vec<u8>, ChatError> {
        self.ctx.create_intro_bundle()
    }
}
