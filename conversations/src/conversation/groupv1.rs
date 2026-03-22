mod frames;

use chat_proto::logoschat::encryption::{EncryptedPayload, Plaintext};
use prost::{Message, bytes::Bytes};
use std::fmt::Debug;
use std::rc::Rc;

use crate::{
    ListConvoResult,
    conversation::{ChatError, ConversationId, Convo, Id},
    errors::EncryptionError,
    identity::Identity,
    proto,
    types::{AddressedEncryptedPayload, ContentData},
    utils::timestamp_millis,
};

use openmls::{prelude::*, treesync::RatchetTree};
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::Provider as LibcruxProvider;

pub struct GroupV1Convo {
    mls_group: MlsGroup,
    account: Rc<Identity>,
    convo_id: String,
}

impl std::fmt::Debug for GroupV1Convo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupV1Convo")
            .field("convo_id", &self.convo_id)
            .finish_non_exhaustive()
    }
}

impl GroupV1Convo {
    pub fn new(account: Rc<Identity>) -> Self {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)
            .build();
        let mls_group = MlsGroup::new(
            account.provider(),
            account.signer(),
            &config,
            account.credential().clone(),
        )
        .unwrap();

        let convo_id = hex::encode(mls_group.group_id().as_slice());

        Self {
            mls_group,
            account,
            convo_id,
        }
    }

    pub fn new_from_welcome(
        account: Rc<Identity>,
        join_config: &MlsGroupJoinConfig,
        welcome: Welcome,
        ratchet_tree: RatchetTreeIn,
    ) -> Self {
        let mls_group = StagedWelcome::build_from_welcome(account.provider(), join_config, welcome)
            .unwrap()
            .with_ratchet_tree(ratchet_tree)
            .build()
            .unwrap()
            .into_group(account.provider())
            .unwrap();

        let convo_id = hex::encode(mls_group.group_id().as_slice());
        GroupV1Convo {
            mls_group,
            account,
            convo_id,
        }
    }

    pub fn add_member(&mut self, keypkgs: &[KeyPackage]) -> (MlsMessageOut, MlsMessageOut) {
        // add_members returns:
        //   commit      — the Commit message Alice broadcasts to all members
        //   welcome     — the Welcome message sent privately to each new joiner
        //   _group_info — used for external joins; ignore for now
        let (commit, welcome, _group_info) = self
            .mls_group
            .add_members(
                self.account.provider(),
                self.account.signer(),
                keypkgs.as_ref(),
            )
            .unwrap();

        self.mls_group
            .merge_pending_commit(self.account.provider())
            .unwrap();

        (commit, welcome)
    }

    pub fn ratchet_tree(&self) -> RatchetTree {
        self.mls_group.export_ratchet_tree()
    }
}

impl Id for GroupV1Convo {
    fn id(&self) -> ConversationId<'_> {
        &self.convo_id
    }
}

impl Convo for GroupV1Convo {
    fn send_message(
        &mut self,
        content: &[u8],
    ) -> Result<Vec<AddressedEncryptedPayload>, ChatError> {
        let mls_message_out = self
            .mls_group
            .create_message(self.account.provider(), self.account.signer(), content)
            .unwrap();

        let a = AddressedEncryptedPayload {
            delivery_address: "group_id_topic".into(),
            data: EncryptedPayload {
                encryption: Some(
                    chat_proto::logoschat::encryption::encrypted_payload::Encryption::Plaintext(
                        Plaintext {
                            payload: mls_message_out.to_bytes().unwrap().into(),
                        },
                    ),
                ),
            },
        };

        Ok(vec![a])
    }

    fn handle_frame(
        &mut self,
        encoded_payload: EncryptedPayload,
    ) -> Result<Option<ContentData>, ChatError> {
        use chat_proto::logoschat::encryption::encrypted_payload::Encryption;

        let bytes = match encoded_payload.encryption {
            Some(Encryption::Plaintext(pt)) => pt.payload,
            _ => {
                return Err(ChatError::ProtocolExpectation(
                    "None",
                    "Some(Encryption::Plaintext)".into(),
                ));
            }
        };

        let mls_message = MlsMessageIn::tls_deserialize_exact_bytes(&bytes)
            .map_err(|_| ChatError::Protocol("TODO".into()))?;

        let protocol_message: ProtocolMessage = mls_message
            .try_into_protocol_message()
            .map_err(|_| ChatError::Protocol("TODO".into()))?;

        let processed = self
            .mls_group
            .process_message(self.account.provider(), protocol_message)
            .map_err(|_| ChatError::Protocol("TODO".into()))?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(msg) => Ok(Some(ContentData {
                conversation_id: hex::encode(self.mls_group.group_id().as_slice()),
                data: msg.into_bytes(),
                is_new_convo: false,
            })),
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                self.mls_group
                    .merge_staged_commit(self.account.provider(), *commit)
                    .map_err(|_| ChatError::Protocol("TODO".into()))?;
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn remote_id(&self) -> String {
        "group_remote_id".into()
    }
}

#[cfg(test)]
mod tests {
    use crypto::PrivateKey;

    use super::*;

    #[test]
    fn test_mls() {
        let saro = Rc::new(Identity::new("saro")); //, &saro_provider);
        let raya = Rc::new(Identity::new("raya")); //, &raya_provider);
        let pax = Rc::new(Identity::new("pax")); //, &pax_provider);

        let mut saro_convo = GroupV1Convo::new(saro);

        let raya_kp = raya.key_package();
        let pax_kp = pax.key_package();

        let (commit, welcome) = saro_convo.add_member(&[raya_kp, pax_kp]);
        let tree = saro_convo.ratchet_tree();
        let MlsMessageBodyOut::Welcome(w) = welcome.body() else {
            panic!("expected Welcome")
        };

        // Bob joins from the Welcome
        let mut raya_convo = GroupV1Convo::new_from_welcome(
            raya.into(),
            &MlsGroupJoinConfig::default(),
            w.clone(),
            // Pass in Alice's ratchet tree so Bob doesn't need to fetch it separately.
            // In a real deployment you'd fetch this from the DS.
            saro_convo.ratchet_tree().into(),
        );

        let mut pax_convo = GroupV1Convo::new_from_welcome(
            pax,
            &MlsGroupJoinConfig::default(),
            w.clone(),
            // Pass in Alice's ratchet tree so Bob doesn't need to fetch it separately.
            // In a real deployment you'd fetch this from the DS.
            saro_convo.ratchet_tree().into(),
        );

        let outbound_messages = saro_convo.send_message("Hi From Saro".as_bytes()).unwrap();

        for msg in outbound_messages {
            let some_content = raya_convo.handle_frame(msg.data.clone()).unwrap();
            if let Some(content) = some_content {
                println!("{} :: {:?}", "Raya", String::from_utf8_lossy(&content.data));
                assert_eq!(content.data, "Hi From Saro".as_bytes());
            }

            let some_content = pax_convo.handle_frame(msg.data).unwrap();
            if let Some(content) = some_content {
                println!("{} :: {:?}", "PAx", String::from_utf8_lossy(&content.data));
                assert_eq!(content.data, "Hi From Saro".as_bytes());
            }
        }
    }
}
