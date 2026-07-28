use openmls::{
    credentials::CredentialType,
    framing::{ProcessedMessage, Sender},
    group::{Member, MlsGroup},
};
use tracing::warn;

use crate::{ChatError, SignerId};

pub fn signer_for_sender(
    mls_group: &MlsGroup,
    processed: &ProcessedMessage,
) -> Result<SignerId, ChatError> {
    // The signature key openmls just verified this message under.
    let sender_sig_key: Vec<u8> = match processed.sender() {
        Sender::Member(leaf_index) => {
            mls_group
                .member_at(*leaf_index)
                .ok_or_else(|| ChatError::generic("sender leaf not in tree"))?
                .signature_key
        }
        // Application/private messages always come from a Member; anything else
        // here is a protocol violation.
        other => {
            return Err(ChatError::generic(format!("unexpected sender: {other:?}")));
        }
    };
    Ok(sender_sig_key.into())
}

#[derive(Debug, Clone)]
pub struct UnverifiedSender {
    pub signer_id: SignerId,
    pub cred: Vec<u8>,
}

impl From<Member> for UnverifiedSender {
    fn from(value: Member) -> Self {
        if CredentialType::Basic != value.credential.credential_type() {
            warn!(credtype = ?value.credential, "Incorrect credentialType");
        };

        let cred = value.credential.serialized_content().to_vec();
        let signer_id = SignerId::from(value.signature_key);

        Self { signer_id, cred }
    }
}
