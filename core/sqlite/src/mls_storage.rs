//! The MLS half of [`ChatStorage`](crate::ChatStorage): its OpenMLS
//! [`StorageProvider`] impl, backed by a `mls_kv(key, value)` table in the same
//! SQLite database as the chat schema.
//!
//! A byte-faithful port of `openmls_memory_storage::MemoryStorage`: the same
//! `label ++ serde_json(logical_key) ++ version_be` key derivation and JSON
//! value encoding, but persisted to the table instead of a `HashMap`, so an MLS
//! group's state survives process restarts (`MlsGroup::load` reads it back)
//! where the in-memory provider cannot.
//!
//! Two deviations from the reference impl, both deliberate:
//!  - decode paths return `Err` instead of `unwrap`ing, since disk bytes can be
//!    corrupt where an in-memory map cannot;
//!  - `clear_proposal_queue` deletes queued proposals with the same composite
//!    key they were written under (the reference impl uses a bare key and
//!    orphans them).

use openmls_traits::storage::*;
use rusqlite::{OptionalExtension, params};

use crate::ChatStorage;

/// Errors surfaced by [`ChatStorage`]'s MLS [`StorageProvider`] impl as its
/// `Error` type.
#[derive(Debug, thiserror::Error)]
pub enum MlsStorageError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("codec: {0}")]
    Codec(#[from] serde_json::Error),
    #[error("inconsistent storage: {0}")]
    Inconsistent(&'static str),
}

// Raw and typed key/value helpers backing the `StorageProvider` impl below. They
// run on the same connection as the chat schema; the trait's all-`&self` API
// maps onto rusqlite's `&self` methods directly, and a `Core` drives storage
// single-threaded so no external synchronization is needed.
impl ChatStorage {
    fn conn(&self) -> &rusqlite::Connection {
        self.db.connection()
    }

    fn put(&self, storage_key: &[u8], value: &[u8]) -> Result<(), MlsStorageError> {
        self.conn().execute(
            "INSERT OR REPLACE INTO mls_kv (key, value) VALUES (?1, ?2)",
            params![storage_key, value],
        )?;
        Ok(())
    }

    fn get(&self, storage_key: &[u8]) -> Result<Option<Vec<u8>>, MlsStorageError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT value FROM mls_kv WHERE key = ?1",
                params![storage_key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?)
    }

    fn del(&self, storage_key: &[u8]) -> Result<(), MlsStorageError> {
        self.conn()
            .execute("DELETE FROM mls_kv WHERE key = ?1", params![storage_key])?;
        Ok(())
    }

    // --- typed helpers mirroring MemoryStorage's private helpers ---

    fn write<const V: u16>(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), MlsStorageError> {
        self.put(&build_key_from_vec::<V>(label, key.to_vec()), &value)
    }

    fn read<const V: u16, E: Entity<V>>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Option<E>, MlsStorageError> {
        match self.get(&build_key_from_vec::<V>(label, key.to_vec()))? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    fn read_list<const V: u16, E: Entity<V>>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Vec<E>, MlsStorageError> {
        let list = self.read_raw_list::<V>(label, key)?;
        list.iter()
            .map(|bytes| serde_json::from_slice(bytes))
            .collect::<Result<Vec<E>, _>>()
            .map_err(MlsStorageError::from)
    }

    /// The raw JSON-array-of-blobs behind a list key (empty when absent).
    fn read_raw_list<const V: u16>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Vec<Vec<u8>>, MlsStorageError> {
        match self.get(&build_key_from_vec::<V>(label, key.to_vec()))? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(vec![]),
        }
    }

    fn append<const V: u16>(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), MlsStorageError> {
        let storage_key = build_key_from_vec::<V>(label, key.to_vec());
        let tx = self.conn().unchecked_transaction()?;
        let mut list = load_list(&tx, &storage_key)?;
        list.push(value);
        store_list(&tx, &storage_key, &list)?;
        tx.commit()?;
        Ok(())
    }

    fn remove_item<const V: u16>(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), MlsStorageError> {
        let storage_key = build_key_from_vec::<V>(label, key.to_vec());
        let tx = self.conn().unchecked_transaction()?;
        let mut list = load_list(&tx, &storage_key)?;
        if let Some(pos) = list.iter().position(|item| item == &value) {
            list.remove(pos);
        }
        store_list(&tx, &storage_key, &list)?;
        tx.commit()?;
        Ok(())
    }

    fn delete<const V: u16>(&self, label: &[u8], key: &[u8]) -> Result<(), MlsStorageError> {
        self.del(&build_key_from_vec::<V>(label, key.to_vec()))
    }
}

fn build_key_from_vec<const V: u16>(label: &[u8], key: Vec<u8>) -> Vec<u8> {
    let mut out = label.to_vec();
    out.extend_from_slice(&key);
    out.extend_from_slice(&u16::to_be_bytes(V));
    out
}

fn epoch_key_pairs_id(
    group_id: &impl traits::GroupId<CURRENT_VERSION>,
    epoch: &impl traits::EpochKey<CURRENT_VERSION>,
    leaf_index: u32,
) -> Result<Vec<u8>, MlsStorageError> {
    let mut key = serde_json::to_vec(group_id)?;
    key.extend_from_slice(&serde_json::to_vec(epoch)?);
    key.extend_from_slice(&serde_json::to_vec(&leaf_index)?);
    Ok(key)
}

fn load_list(
    tx: &rusqlite::Transaction<'_>,
    storage_key: &[u8],
) -> Result<Vec<Vec<u8>>, MlsStorageError> {
    let existing: Option<Vec<u8>> = tx
        .query_row(
            "SELECT value FROM mls_kv WHERE key = ?1",
            params![storage_key],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    match existing {
        Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
        None => Ok(vec![]),
    }
}

fn store_list(
    tx: &rusqlite::Transaction<'_>,
    storage_key: &[u8],
    list: &[Vec<u8>],
) -> Result<(), MlsStorageError> {
    let encoded = serde_json::to_vec(list)?;
    tx.execute(
        "INSERT OR REPLACE INTO mls_kv (key, value) VALUES (?1, ?2)",
        params![storage_key, encoded],
    )?;
    Ok(())
}

const KEY_PACKAGE_LABEL: &[u8] = b"KeyPackage";
const PSK_LABEL: &[u8] = b"Psk";
const ENCRYPTION_KEY_PAIR_LABEL: &[u8] = b"EncryptionKeyPair";
const SIGNATURE_KEY_PAIR_LABEL: &[u8] = b"SignatureKeyPair";
const EPOCH_KEY_PAIRS_LABEL: &[u8] = b"EpochKeyPairs";

const TREE_LABEL: &[u8] = b"Tree";
const GROUP_CONTEXT_LABEL: &[u8] = b"GroupContext";
const INTERIM_TRANSCRIPT_HASH_LABEL: &[u8] = b"InterimTranscriptHash";
const CONFIRMATION_TAG_LABEL: &[u8] = b"ConfirmationTag";

const JOIN_CONFIG_LABEL: &[u8] = b"MlsGroupJoinConfig";
const OWN_LEAF_NODES_LABEL: &[u8] = b"OwnLeafNodes";
const GROUP_STATE_LABEL: &[u8] = b"GroupState";
const QUEUED_PROPOSAL_LABEL: &[u8] = b"QueuedProposal";
const PROPOSAL_QUEUE_REFS_LABEL: &[u8] = b"ProposalQueueRefs";
const OWN_LEAF_NODE_INDEX_LABEL: &[u8] = b"OwnLeafNodeIndex";
const EPOCH_SECRETS_LABEL: &[u8] = b"EpochSecrets";
const RESUMPTION_PSK_STORE_LABEL: &[u8] = b"ResumptionPsk";
const MESSAGE_SECRETS_LABEL: &[u8] = b"MessageSecrets";

impl StorageProvider<CURRENT_VERSION> for ChatStorage {
    type Error = MlsStorageError;

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(&(group_id, proposal_ref))?;
        let value = serde_json::to_vec(proposal)?;
        self.write::<CURRENT_VERSION>(QUEUED_PROPOSAL_LABEL, &key, value)?;

        let key = serde_json::to_vec(group_id)?;
        let value = serde_json::to_vec(proposal_ref)?;
        self.append::<CURRENT_VERSION>(PROPOSAL_QUEUE_REFS_LABEL, &key, value)
    }

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            TREE_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(tree)?,
        )
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            INTERIM_TRANSCRIPT_HASH_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(interim_transcript_hash)?,
        )
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            GROUP_CONTEXT_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(group_context)?,
        )
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            CONFIRMATION_TAG_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(confirmation_tag)?,
        )
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            SIGNATURE_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key)?,
            serde_json::to_vec(signature_key_pair)?,
        )
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.read_list::<CURRENT_VERSION, _>(
            PROPOSAL_QUEUE_REFS_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        let refs: Vec<ProposalRef> = self.read_list::<CURRENT_VERSION, _>(
            PROPOSAL_QUEUE_REFS_LABEL,
            &serde_json::to_vec(group_id)?,
        )?;

        refs.into_iter()
            .map(|proposal_ref| {
                let key = serde_json::to_vec(&(group_id, &proposal_ref))?;
                let proposal = self
                    .read::<CURRENT_VERSION, _>(QUEUED_PROPOSAL_LABEL, &key)?
                    .ok_or(MlsStorageError::Inconsistent(
                        "queued proposal missing for stored reference",
                    ))?;
                Ok((proposal_ref, proposal))
            })
            .collect::<Result<Vec<_>, Self::Error>>()
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        self.read::<CURRENT_VERSION, _>(TREE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        self.read::<CURRENT_VERSION, _>(GROUP_CONTEXT_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        self.read::<CURRENT_VERSION, _>(
            INTERIM_TRANSCRIPT_HASH_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        self.read::<CURRENT_VERSION, _>(CONFIRMATION_TAG_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        self.read::<CURRENT_VERSION, _>(SIGNATURE_KEY_PAIR_LABEL, &serde_json::to_vec(public_key)?)
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            KEY_PACKAGE_LABEL,
            &serde_json::to_vec(hash_ref)?,
            serde_json::to_vec(key_package)?,
        )
    }

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            PSK_LABEL,
            &serde_json::to_vec(psk_id)?,
            serde_json::to_vec(psk)?,
        )
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key)?,
            serde_json::to_vec(key_pair)?,
        )
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        self.read::<CURRENT_VERSION, _>(KEY_PACKAGE_LABEL, &serde_json::to_vec(hash_ref)?)
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.read::<CURRENT_VERSION, _>(PSK_LABEL, &serde_json::to_vec(psk_id)?)
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.read::<CURRENT_VERSION, _>(ENCRYPTION_KEY_PAIR_LABEL, &serde_json::to_vec(public_key)?)
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(SIGNATURE_KEY_PAIR_LABEL, &serde_json::to_vec(public_key)?)
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(ENCRYPTION_KEY_PAIR_LABEL, &serde_json::to_vec(public_key)?)
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(KEY_PACKAGE_LABEL, &serde_json::to_vec(hash_ref)?)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(PSK_LABEL, &serde_json::to_vec(psk_id)?)
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.read::<CURRENT_VERSION, _>(GROUP_STATE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            GROUP_STATE_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(group_state)?,
        )
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(GROUP_STATE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.read::<CURRENT_VERSION, _>(MESSAGE_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            MESSAGE_SECRETS_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(message_secrets)?,
        )
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(MESSAGE_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.read::<CURRENT_VERSION, _>(RESUMPTION_PSK_STORE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            RESUMPTION_PSK_STORE_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(resumption_psk_store)?,
        )
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(RESUMPTION_PSK_STORE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.read::<CURRENT_VERSION, _>(OWN_LEAF_NODE_INDEX_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            OWN_LEAF_NODE_INDEX_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(own_leaf_index)?,
        )
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(OWN_LEAF_NODE_INDEX_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.read::<CURRENT_VERSION, _>(EPOCH_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            EPOCH_SECRETS_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(group_epoch_secrets)?,
        )
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(EPOCH_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        let value = serde_json::to_vec(key_pairs)?;
        self.write::<CURRENT_VERSION>(EPOCH_KEY_PAIRS_LABEL, &key, value)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        match self.get(&build_key_from_vec::<CURRENT_VERSION>(
            EPOCH_KEY_PAIRS_LABEL,
            key,
        ))? {
            Some(bytes) => Ok(serde_json::from_slice(&bytes)?),
            None => Ok(vec![]),
        }
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        self.delete::<CURRENT_VERSION>(EPOCH_KEY_PAIRS_LABEL, &key)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let proposal_refs: Vec<ProposalRef> = self.read_list::<CURRENT_VERSION, _>(
            PROPOSAL_QUEUE_REFS_LABEL,
            &serde_json::to_vec(group_id)?,
        )?;

        for proposal_ref in proposal_refs {
            // Delete under the same composite key `queue_proposal` wrote it with;
            // the reference impl uses a bare key here and orphans these rows.
            let key = serde_json::to_vec(&(group_id, &proposal_ref))?;
            self.delete::<CURRENT_VERSION>(QUEUED_PROPOSAL_LABEL, &key)?;
        }

        self.delete::<CURRENT_VERSION>(PROPOSAL_QUEUE_REFS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.read::<CURRENT_VERSION, _>(JOIN_CONFIG_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            JOIN_CONFIG_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(config)?,
        )
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.read_list::<CURRENT_VERSION, _>(OWN_LEAF_NODES_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(group_id)?;
        let value = serde_json::to_vec(leaf_node)?;
        self.append::<CURRENT_VERSION>(OWN_LEAF_NODES_LABEL, &key, value)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(OWN_LEAF_NODES_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(JOIN_CONFIG_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(TREE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(CONFIRMATION_TAG_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(GROUP_CONTEXT_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(
            INTERIM_TRANSCRIPT_HASH_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(group_id)?;
        let value = serde_json::to_vec(proposal_ref)?;
        self.remove_item::<CURRENT_VERSION>(PROPOSAL_QUEUE_REFS_LABEL, &key, value)?;

        let key = serde_json::to_vec(&(group_id, proposal_ref))?;
        self.delete::<CURRENT_VERSION>(QUEUED_PROPOSAL_LABEL, &key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::StorageConfig;

    // Minimal Key/Entity newtypes so the KV layer can be exercised without
    // dragging in openmls' concrete group types.
    #[derive(serde::Serialize)]
    struct TestKey(Vec<u8>);
    impl Key<CURRENT_VERSION> for TestKey {}
    impl traits::GroupId<CURRENT_VERSION> for TestKey {}

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
    struct TestVal(u32);
    impl Entity<CURRENT_VERSION> for TestVal {}
    impl traits::GroupState<CURRENT_VERSION> for TestVal {}
    impl traits::LeafNode<CURRENT_VERSION> for TestVal {}

    fn store() -> ChatStorage {
        ChatStorage::in_memory()
    }

    #[test]
    fn single_value_round_trip() {
        let s = store();
        let gid = TestKey(b"group-a".to_vec());

        assert_eq!(s.group_state::<TestVal, _>(&gid).unwrap(), None);
        s.write_group_state(&gid, &TestVal(7)).unwrap();
        assert_eq!(s.group_state::<TestVal, _>(&gid).unwrap(), Some(TestVal(7)));

        // Overwrite replaces in place.
        s.write_group_state(&gid, &TestVal(9)).unwrap();
        assert_eq!(s.group_state::<TestVal, _>(&gid).unwrap(), Some(TestVal(9)));

        s.delete_group_state(&gid).unwrap();
        assert_eq!(s.group_state::<TestVal, _>(&gid).unwrap(), None);
    }

    #[test]
    fn list_append_and_read() {
        let s = store();
        let gid = TestKey(b"group-b".to_vec());

        assert!(s.own_leaf_nodes::<_, TestVal>(&gid).unwrap().is_empty());
        s.append_own_leaf_node(&gid, &TestVal(1)).unwrap();
        s.append_own_leaf_node(&gid, &TestVal(2)).unwrap();

        let nodes: Vec<TestVal> = s.own_leaf_nodes(&gid).unwrap();
        assert_eq!(nodes, vec![TestVal(1), TestVal(2)]);

        s.delete_own_leaf_nodes(&gid).unwrap();
        assert!(s.own_leaf_nodes::<_, TestVal>(&gid).unwrap().is_empty());
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mls.db").to_str().unwrap().to_string();
        let gid = TestKey(b"group-c".to_vec());

        {
            let s = ChatStorage::new(StorageConfig::File(path.clone())).unwrap();
            s.write_group_state(&gid, &TestVal(42)).unwrap();
        }

        let reopened = ChatStorage::new(StorageConfig::File(path)).unwrap();
        assert_eq!(
            reopened.group_state::<TestVal, _>(&gid).unwrap(),
            Some(TestVal(42))
        );
    }
}
