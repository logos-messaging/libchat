use libchat::ChatError;

#[derive(Debug, thiserror::Error)]
pub enum ClientError<D: std::fmt::Debug> {
    #[error(transparent)]
    Chat(#[from] ChatError),
    /// Crypto state advanced but at least one envelope failed delivery.
    /// Caller decides whether to retry.
    #[error("delivery failed: {0:?}")]
    Delivery(D),
}
