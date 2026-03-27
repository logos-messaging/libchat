use storage::StorageError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationKind {
    PrivateV1,
    Unknown(String),
}

impl ConversationKind {
    pub fn from_db(value: &str) -> Self {
        match value {
            "private_v1" => Self::PrivateV1,
            other => Self::Unknown(other.to_string()),
        }
    }

    pub fn as_db(&self) -> &str {
        match self {
            Self::PrivateV1 => "private_v1",
            Self::Unknown(value) => value.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationMeta {
    pub local_convo_id: String,
    pub remote_convo_id: String,
    pub kind: ConversationKind,
}

pub trait ConversationStore {
    fn save_conversation(&mut self, meta: &ConversationMeta) -> Result<(), StorageError>;

    fn load_conversation(
        &self,
        local_convo_id: &str,
    ) -> Result<Option<ConversationMeta>, StorageError>;

    fn remove_conversation(&mut self, local_convo_id: &str) -> Result<(), StorageError>;

    fn load_conversations(&self) -> Result<Vec<ConversationMeta>, StorageError>;

    fn has_conversation(&self, local_convo_id: &str) -> Result<bool, StorageError>;
}
