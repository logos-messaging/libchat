use std::{collections::HashMap, marker::PhantomData};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};
use x25519_dalek::PublicKey;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    aead::{decrypt, encrypt},
    errors::RatchetError,
    hkdf::{DefaultDomain, HkdfInfo, kdf_chain, kdf_root},
    keypair::InstallationKeyPair,
    reader::Reader,
    types::{ChainKey, MessageKey, Nonce, RootKey, SharedSecret},
};

/// Current binary format version.
const SERIALIZATION_VERSION: u8 = 1;

/// Represents the local state of the Double Ratchet algorithm for one conversation.
///
/// This struct maintains all keys and counters required to perform the Double Ratchet
/// as specified in the Signal protocol, providing end-to-end encryption with forward
/// secrecy and post-compromise security.
#[derive(Clone)]
pub struct RatchetState<D: HkdfInfo = DefaultDomain> {
    pub root_key: RootKey,

    pub sending_chain: Option<ChainKey>,
    pub receiving_chain: Option<ChainKey>,

    pub dh_self: InstallationKeyPair,
    pub dh_remote: Option<PublicKey>,

    pub msg_send: u32,
    pub msg_recv: u32,
    pub prev_chain_len: u32,

    pub skipped_keys: HashMap<(PublicKey, u32), MessageKey>,

    pub(crate) _domain: PhantomData<D>,
}

/// Represents a skipped message key for storage or inspection.
#[derive(Debug, Clone)]
pub struct SkippedKey {
    pub public_key: [u8; 32],
    pub msg_num: u32,
    pub message_key: MessageKey,
}

impl<D: HkdfInfo> RatchetState<D> {
    /// Serializes the ratchet state to a binary format.
    ///
    /// # Binary Format (Version 1)
    ///
    /// ```text
    /// | Field              | Size (bytes) | Description                          |
    /// |--------------------|--------------|--------------------------------------|
    /// | version            | 1            | Format version (0x01)                |
    /// | root_key           | 32           | Root key                             |
    /// | sending_chain_flag | 1            | 0x00 = None, 0x01 = Some             |
    /// | sending_chain      | 0 or 32      | Chain key if flag is 0x01            |
    /// | receiving_chain_flag| 1           | 0x00 = None, 0x01 = Some             |
    /// | receiving_chain    | 0 or 32      | Chain key if flag is 0x01            |
    /// | dh_self_secret     | 32           | DH secret key                        |
    /// | dh_remote_flag     | 1            | 0x00 = None, 0x01 = Some             |
    /// | dh_remote          | 0 or 32      | DH public key if flag is 0x01        |
    /// | msg_send           | 4            | Send counter (big-endian)            |
    /// | msg_recv           | 4            | Receive counter (big-endian)         |
    /// | prev_chain_len     | 4            | Previous chain length (big-endian)   |
    /// | skipped_count      | 4            | Number of skipped keys (big-endian)  |
    /// | skipped_keys       | 68 * count   | Each: pubkey(32) + msg_num(4) + key(32) |
    /// ```
    pub fn as_bytes(&self) -> Zeroizing<Vec<u8>> {
        fn option_size(opt: Option<[u8; 32]>) -> usize {
            1 + opt.map_or(0, |_| 32)
        }

        fn write_option(buf: &mut Vec<u8>, opt: Option<[u8; 32]>) {
            match opt {
                Some(data) => {
                    buf.push(0x01);
                    buf.extend_from_slice(&data);
                }
                None => buf.push(0x00),
            }
        }

        let skipped_count = self.skipped_keys.len();
        let dh_remote = self.dh_remote.map(|pk| pk.to_bytes());

        let capacity = 1 + 32  // version + root_key
            + option_size(self.sending_chain)
            + option_size(self.receiving_chain)
            + 32  // dh_self
            + option_size(dh_remote)
            + 12  // counters
            + 4 + (skipped_count * 68); // skipped keys

        let mut buf = Zeroizing::new(Vec::with_capacity(capacity));

        buf.push(SERIALIZATION_VERSION);
        buf.extend_from_slice(&self.root_key);
        write_option(&mut buf, self.sending_chain);
        write_option(&mut buf, self.receiving_chain);

        let dh_secret = self.dh_self.secret_bytes();
        buf.extend_from_slice(dh_secret);

        write_option(&mut buf, dh_remote);

        buf.extend_from_slice(&self.msg_send.to_be_bytes());
        buf.extend_from_slice(&self.msg_recv.to_be_bytes());
        buf.extend_from_slice(&self.prev_chain_len.to_be_bytes());

        buf.extend_from_slice(&(skipped_count as u32).to_be_bytes());
        for ((pk, msg_num), mk) in &self.skipped_keys {
            buf.extend_from_slice(pk.as_bytes());
            buf.extend_from_slice(&msg_num.to_be_bytes());
            buf.extend_from_slice(mk);
        }

        buf
    }

    /// Deserializes a ratchet state from binary data.
    ///
    /// # Errors
    ///
    /// Returns `RatchetError::DeserializationFailed` if the data is invalid or truncated.
    pub fn from_bytes(data: &[u8]) -> Result<Self, RatchetError> {
        let mut reader = Reader::new(data);

        let version = reader.read_u8()?;
        if version != SERIALIZATION_VERSION {
            return Err(RatchetError::DeserializationFailed);
        }

        let root_key: RootKey = reader.read_array()?;
        let sending_chain = reader.read_option()?;
        let receiving_chain = reader.read_option()?;

        let mut dh_self_bytes: [u8; 32] = reader.read_array()?;
        let dh_self = InstallationKeyPair::from_secret_bytes(dh_self_bytes);
        dh_self_bytes.zeroize();

        let dh_remote = reader.read_option()?.map(PublicKey::from);

        let msg_send = reader.read_u32()?;
        let msg_recv = reader.read_u32()?;
        let prev_chain_len = reader.read_u32()?;

        let skipped_count = reader.read_u32()? as usize;
        let mut skipped_keys = HashMap::with_capacity(skipped_count);
        for _ in 0..skipped_count {
            let pk = PublicKey::from(reader.read_array::<32>()?);
            let msg_num = reader.read_u32()?;
            let mk: MessageKey = reader.read_array()?;
            skipped_keys.insert((pk, msg_num), mk);
        }

        Ok(Self {
            root_key,
            sending_chain,
            receiving_chain,
            dh_self,
            dh_remote,
            msg_send,
            msg_recv,
            prev_chain_len,
            skipped_keys,
            _domain: PhantomData,
        })
    }
}

/// Custom serde Serialize implementation that uses our binary format.
impl<D: HkdfInfo> Serialize for RatchetState<D> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.as_bytes())
    }
}

/// Custom serde Deserialize implementation that uses our binary format.
impl<'de, D: HkdfInfo> Deserialize<'de> for RatchetState<D> {
    fn deserialize<De>(deserializer: De) -> Result<Self, De::Error>
    where
        De: Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(DeError::custom)
    }
}

/// Public header attached to every encrypted message (unencrypted but authenticated).
#[derive(Clone, Debug)]
pub struct Header {
    pub dh_pub: PublicKey,
    pub msg_num: u32,
    pub prev_chain_len: u32,
}

impl Header {
    /// Serializes the full header for use as Associated Authenticated Data (AAD).
    /// Format: DH public key (32 bytes) || message number (4 bytes, big-endian) || previous chain length (4 bytes, big-endian)
    ///
    /// # Returns
    ///
    /// A 40-byte slice containing the serialized header.
    pub fn serialized(&self) -> [u8; 40] {
        let mut aad = [0u8; 40];
        aad[0..32].copy_from_slice(self.dh_pub.as_bytes());
        aad[32..36].copy_from_slice(&self.msg_num.to_be_bytes());
        aad[36..40].copy_from_slice(&self.prev_chain_len.to_be_bytes());
        aad
    }
}

impl<D: HkdfInfo> RatchetState<D> {
    /// Initializes the party that sends the first message.
    ///
    /// Performs the initial Diffie-Hellman computation with the remote public key
    /// and derives the initial root and sending chain keys.
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - Pre-shared secret (e.g., from X3DH).
    /// * `remote_pub`    - Remote party's public key for the initial DH.
    ///
    /// # Returns
    ///
    /// A new `RatchetState` ready to send the first message.
    pub fn init_sender(shared_secret: SharedSecret, remote_pub: PublicKey) -> Self {
        let dh_self = InstallationKeyPair::generate();

        // Initial DH
        let dh_out = dh_self.dh(&remote_pub);
        let (root_key, sending_chain) = kdf_root::<D>(&shared_secret, &dh_out);

        Self {
            root_key,

            sending_chain: Some(sending_chain),
            receiving_chain: None,

            dh_self,
            dh_remote: Some(remote_pub),

            msg_send: 0,
            msg_recv: 0,
            prev_chain_len: 0,

            skipped_keys: HashMap::new(),

            _domain: PhantomData,
        }
    }

    /// Initializes the party that receives the first message.
    ///
    /// No chain keys are derived yet — they will be created upon receiving the first message.
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - Pre-shared secret (e.g., from X3DH).
    /// * `dh_self`       - Our long-term or initial DH key pair.
    ///
    /// # Returns
    ///
    /// A new `RatchetState` ready to receive the first message.
    pub fn init_receiver(shared_secret: SharedSecret, dh_self: InstallationKeyPair) -> Self {
        Self {
            root_key: shared_secret,

            sending_chain: None,
            receiving_chain: None, // derived on first receive

            dh_self,
            dh_remote: None,

            msg_send: 0,
            msg_recv: 0,
            prev_chain_len: 0,

            skipped_keys: HashMap::new(),

            _domain: PhantomData,
        }
    }

    /// Performs a receiving-side DH ratchet when a new remote DH public key is observed.
    ///
    /// # Arguments
    ///
    /// * `remote_pub` - The new DH public key from the sender.
    pub fn dh_ratchet_receive(&mut self, remote_pub: PublicKey) {
        let dh_out = self.dh_self.dh(&remote_pub);
        let (new_root, recv_chain) = kdf_root::<D>(&self.root_key, &dh_out);

        self.root_key = new_root;
        self.receiving_chain = Some(recv_chain);
        self.sending_chain = None; // 🔥 important
        self.dh_remote = Some(remote_pub);
        self.msg_recv = 0;
    }

    /// Performs a sending-side DH ratchet (generates new key pair and advances root key).
    /// Called automatically when sending but no active sending chain exists.
    pub fn dh_ratchet_send(&mut self) {
        let remote = self.dh_remote.expect("no remote DH key");

        self.dh_self = InstallationKeyPair::generate();
        let dh_out = self.dh_self.dh(&remote);
        let (new_root, send_chain) = kdf_root::<D>(&self.root_key, &dh_out);

        self.root_key = new_root;
        self.sending_chain = Some(send_chain);
    }

    /// Encrypts a plaintext message.
    ///
    /// Automatically performs a DH ratchet if the sending direction has changed.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The message to encrypt.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * The ciphertext prefixed with the nonce.
    /// * The `Header` that must be sent alongside the ciphertext.
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> (Vec<u8>, Header) {
        if self.sending_chain.is_none() {
            self.dh_ratchet_send();
            self.prev_chain_len = self.msg_send;
            self.msg_send = 0;
        }

        let chain = self.sending_chain.as_mut().unwrap();
        let (next_chain, message_key) = kdf_chain(chain);
        *chain = next_chain;

        let header = Header {
            dh_pub: *self.dh_self.public(),
            msg_num: self.msg_send,
            prev_chain_len: self.prev_chain_len,
        };

        self.msg_send += 1;

        let (ciphertext, nonce) = encrypt(&message_key, plaintext, &header.serialized());

        let mut ciphertext_with_nonce = Vec::with_capacity(nonce.len() + ciphertext.len());
        ciphertext_with_nonce.extend_from_slice(&nonce);
        ciphertext_with_nonce.extend_from_slice(&ciphertext);

        (ciphertext_with_nonce, header)
    }

    /// Decrypts a received message.
    ///
    /// Handles DH ratcheting, skipped messages, and replay protection.
    ///
    /// # Arguments
    ///
    /// * `ciphertext_with_nonce` - Ciphertext prefixed with 12-byte nonce.
    /// * `header`                - The header received with the message.
    ///
    /// # Returns
    ///
    /// * `Ok(plaintext)` on success.
    /// * `Err(String)` on failure (e.g., authentication error, replay, too many skipped).
    pub fn decrypt_message(
        &mut self,
        ciphertext_with_nonce: &[u8],
        header: Header,
    ) -> Result<Vec<u8>, RatchetError> {
        if ciphertext_with_nonce.len() < 12 {
            return Err(RatchetError::CiphertextTooShort);
        }
        let (nonce_slice, ciphertext) = ciphertext_with_nonce.split_at(12);
        let nonce: &Nonce = nonce_slice
            .try_into()
            .map_err(|_| RatchetError::InvalidNonce)?;

        let key_id = (header.dh_pub, header.msg_num);
        if let Some(msg_key) = self.skipped_keys.remove(&key_id) {
            return decrypt(&msg_key, ciphertext, nonce, &header.serialized())
                .map_err(|_| RatchetError::DecryptionFailed);
        }

        if self.dh_remote.as_ref() == Some(&header.dh_pub) && header.msg_num < self.msg_recv {
            return Err(RatchetError::MessageReplay);
        }

        if self.dh_remote.as_ref() != Some(&header.dh_pub) {
            self.skip_message_keys(header.prev_chain_len)?;
            self.dh_ratchet_receive(header.dh_pub);
            self.prev_chain_len = header.msg_num; // Important: update prev_chain_len after ratchet
        }

        self.skip_message_keys(header.msg_num)?;

        let chain = self
            .receiving_chain
            .as_mut()
            .ok_or(RatchetError::MissingReceivingChain)?;
        let (next_chain, message_key) = kdf_chain(chain);

        *chain = next_chain;
        self.msg_recv += 1;

        decrypt(&message_key, ciphertext, nonce, &header.serialized())
            .map_err(|_| RatchetError::DecryptionFailed)
    }

    /// Advances the receiving chain and stores skipped message keys.
    ///
    /// # Arguments
    ///
    /// * `until` - The message number to skip up to (exclusive).
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success.
    /// * `Err(&'static str)` if too many messages would be skipped (DoS protection).
    pub fn skip_message_keys(&mut self, until: u32) -> Result<(), RatchetError> {
        const MAX_SKIP: u32 = 10;

        if self.msg_recv + MAX_SKIP < until {
            return Err(RatchetError::TooManySkippedMessages);
        }

        while self.msg_recv < until {
            let chain = self
                .receiving_chain
                .as_mut()
                .ok_or(RatchetError::MissingReceivingChain)?;
            let (next_chain, msg_key) = kdf_chain(chain);
            *chain = next_chain;

            let remote = self.dh_remote.ok_or(RatchetError::MissingRemoteDhKey)?;
            let key_id = (remote, self.msg_recv);
            self.skipped_keys.insert(key_id, msg_key);
            self.msg_recv += 1;
        }

        Ok(())
    }

    /// Exports the skipped keys for storage or inspection.
    ///
    /// # Returns
    ///
    /// A vector of `SkippedKey` representing the currently stored skipped message keys.
    pub fn skipped_keys(&self) -> Vec<SkippedKey> {
        self.skipped_keys
            .iter()
            .map(|((pk, msg_num), mk)| SkippedKey {
                public_key: pk.to_bytes(),
                msg_num: *msg_num,
                message_key: *mk,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_alice_bob() -> (RatchetState, RatchetState, SharedSecret) {
        // Simulate pre-shared secret (e.g., from X3DH)
        let shared_secret = [0x42; 32];

        // Bob generates his long-term keypair
        let bob_keypair = InstallationKeyPair::generate();

        // Alice initializes as sender, knowing Bob's public key
        let alice = RatchetState::init_sender(shared_secret, *bob_keypair.public());

        // Bob initializes as receiver with his private key
        let bob = RatchetState::init_receiver(shared_secret, bob_keypair);

        (alice, bob, shared_secret)
    }

    #[test]
    fn test_basic_roundtrip_one_message() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        let plaintext = b"Hello Bob, this is Alice!";

        let (ciphertext_with_nonce, header) = alice.encrypt_message(plaintext);

        let decrypted = bob.decrypt_message(&ciphertext_with_nonce, header).unwrap();

        assert_eq!(decrypted, plaintext);
        assert_eq!(alice.msg_send, 1);
        assert_eq!(bob.msg_recv, 1);
    }

    #[test]
    fn test_multiple_messages_in_order() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        let messages = [b"Message 1", b"Message 2", b"message 3"];

        for msg in messages {
            let (ct, header) = alice.encrypt_message(msg);
            let pt = bob.decrypt_message(&ct, header).unwrap();
            assert_eq!(pt, msg);
        }

        assert_eq!(alice.msg_send, 3);
        assert_eq!(bob.msg_recv, 3);
    }

    #[test]
    fn test_out_of_order_messages_with_skipped_keys() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        // Alice sends 3 messages
        let mut sent = vec![];
        for i in 0..3 {
            let plaintext = format!("Message {}", i + 1).into_bytes();
            let (ct, header) = alice.encrypt_message(&plaintext);
            sent.push((ct, header, plaintext));
        }

        // Bob receives them out of order: 0, 2, 1
        let decrypted0 = bob.decrypt_message(&sent[0].0, sent[0].1.clone()).unwrap();
        assert_eq!(decrypted0, sent[0].2);

        let decrypted2 = bob.decrypt_message(&sent[2].0, sent[2].1.clone()).unwrap();
        assert_eq!(decrypted2, sent[2].2);

        let decrypted1 = bob.decrypt_message(&sent[1].0, sent[1].1.clone()).unwrap();
        assert_eq!(decrypted1, sent[1].2);

        assert_eq!(bob.msg_recv, 3);
    }

    #[test]
    fn test_sender_ratchets_after_receiving_from_other_side() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        // Alice sends one message
        let (ct, header) = alice.encrypt_message(b"first");
        bob.decrypt_message(&ct, header).unwrap();

        // Bob performs DH ratchet by trying to send
        let old_bob_pub = *bob.dh_self.public();
        let (bob_ct, bob_header) = {
            let mut b = bob.clone();
            b.encrypt_message(b"reply")
        };
        assert_ne!(bob_header.dh_pub, old_bob_pub);

        // Alice receives Bob's message with new DH pub → ratchets
        let old_alice_pub = *alice.dh_self.public();
        let old_root = alice.root_key;

        // Even if decrypt fails (wrong key), ratchet should happen
        alice.decrypt_message(&bob_ct, bob_header).unwrap();

        // Now Alice sends → should do DH ratchet
        let (_, final_header) = alice.encrypt_message(b"after both ratcheted");

        assert_ne!(final_header.dh_pub, old_alice_pub);
        assert_ne!(alice.root_key, old_root);
    }

    #[test]
    fn test_max_skip_limit_enforced() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        // Alice sends message 0
        let (_, _) = alice.encrypt_message(b"First");

        // Now Alice skips many messages (simulate lost packets)
        for _ in 0..15 {
            alice.encrypt_message(b"lost");
        }

        // Alice sends final message
        let (ct_final, header_final) = alice.encrypt_message(b"Final");

        // Bob tries to decrypt final — should fail because too many skipped
        let result = bob.decrypt_message(&ct_final, header_final);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), RatchetError::TooManySkippedMessages);
    }

    #[test]
    fn test_aad_authenticates_header() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        let (ct, mut header) = alice.encrypt_message(b"Sensitive data");

        // Tamper with header (change DH pub byte)
        let mut tampered_pub_bytes = header.dh_pub.to_bytes();
        tampered_pub_bytes[0] ^= 0xff;
        header.dh_pub = PublicKey::from(tampered_pub_bytes);

        let result = bob.decrypt_message(&ct, header);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), RatchetError::DecryptionFailed);
    }

    #[test]
    fn test_full_asymmetric_ratchet_conversation() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        // Alice sends first few
        for i in 0..3 {
            let msg = format!("A -> B {}", i).into_bytes();
            let (ct, h) = alice.encrypt_message(&msg);
            let pt = bob.decrypt_message(&ct, h).unwrap();
            assert_eq!(pt, msg);
        }

        // Bob now responds — this should trigger his first DH ratchet
        let (ct_b, h_b) = bob.encrypt_message(b"B -> A response");

        // Alice receives Bob's message
        let pt_a = alice.decrypt_message(&ct_b, h_b).unwrap();
        assert_eq!(pt_a, b"B -> A response");

        // Both should now have performed a DH ratchet
        assert!(alice.receiving_chain.is_some());
        assert!(bob.sending_chain.is_some());
    }

    #[test]
    fn test_skipped_keys_are_one_time_use() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        let msgs = vec![b"msg0", b"msg1", b"msg2", b"msg3"];

        let mut encrypted = vec![];
        for msg in msgs {
            let (ct, h) = alice.encrypt_message(msg);
            encrypted.push((ct, h));
        }

        // Receive msg0 and msg2 → msg1 goes to skipped
        bob.decrypt_message(&encrypted[0].0, encrypted[0].1.clone())
            .unwrap();
        bob.decrypt_message(&encrypted[2].0, encrypted[2].1.clone())
            .unwrap();

        // Now receive msg1 — should use skipped key and remove it
        let pt1 = bob
            .decrypt_message(&encrypted[1].0, encrypted[1].1.clone())
            .unwrap();
        assert_eq!(pt1, b"msg1");

        // Try to decrypt msg1 again → should fail (key was removed)
        let result = bob.decrypt_message(&encrypted[1].0, encrypted[1].1.clone());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), RatchetError::MessageReplay);
    }

    #[test]
    fn test_serialize_deserialize_sender_state() {
        let (alice, _, _) = setup_alice_bob();

        // Serialize to binary
        let bytes = alice.as_bytes();

        // Deserialize back
        let restored: RatchetState = RatchetState::from_bytes(&bytes).unwrap();

        // Verify key fields match
        assert_eq!(alice.root_key, restored.root_key);
        assert_eq!(alice.sending_chain, restored.sending_chain);
        assert_eq!(alice.receiving_chain, restored.receiving_chain);
        assert_eq!(alice.msg_send, restored.msg_send);
        assert_eq!(alice.msg_recv, restored.msg_recv);
        assert_eq!(alice.prev_chain_len, restored.prev_chain_len);
        assert_eq!(
            alice.dh_remote.map(|pk| pk.to_bytes()),
            restored.dh_remote.map(|pk| pk.to_bytes())
        );
        assert_eq!(
            alice.dh_self.public().to_bytes(),
            restored.dh_self.public().to_bytes()
        );
    }

    #[test]
    fn test_serialize_deserialize_receiver_state() {
        let (_, bob, _) = setup_alice_bob();

        // Serialize to binary
        let bytes = bob.as_bytes();

        // Deserialize back
        let restored: RatchetState = RatchetState::from_bytes(&bytes).unwrap();

        // Verify key fields match
        assert_eq!(bob.root_key, restored.root_key);
        assert_eq!(bob.sending_chain, restored.sending_chain);
        assert_eq!(bob.receiving_chain, restored.receiving_chain);
        assert_eq!(bob.msg_send, restored.msg_send);
        assert_eq!(bob.msg_recv, restored.msg_recv);
        assert_eq!(bob.prev_chain_len, restored.prev_chain_len);
        assert!(bob.dh_remote.is_none());
        assert!(restored.dh_remote.is_none());
    }

    #[test]
    fn test_serialize_deserialize_with_skipped_keys() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        // Alice sends 3 messages
        let mut sent = vec![];
        for i in 0..3 {
            let plaintext = format!("Message {}", i + 1).into_bytes();
            let (ct, header) = alice.encrypt_message(&plaintext);
            sent.push((ct, header, plaintext));
        }

        // Bob receives only msg0 and msg2, skipping msg1
        bob.decrypt_message(&sent[0].0, sent[0].1.clone()).unwrap();
        bob.decrypt_message(&sent[2].0, sent[2].1.clone()).unwrap();

        // Bob should have one skipped key
        assert_eq!(bob.skipped_keys.len(), 1);

        // Serialize Bob's state
        let bytes = bob.as_bytes();

        // Deserialize
        let mut restored: RatchetState = RatchetState::from_bytes(&bytes).unwrap();

        // Restored state should have the skipped key
        assert_eq!(restored.skipped_keys.len(), 1);

        // The restored state should be able to decrypt the skipped message
        let pt1 = restored
            .decrypt_message(&sent[1].0, sent[1].1.clone())
            .unwrap();
        assert_eq!(pt1, sent[1].2);
    }

    #[test]
    fn test_serialize_deserialize_continue_conversation() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        // Exchange some messages
        let (ct1, h1) = alice.encrypt_message(b"Hello Bob");
        bob.decrypt_message(&ct1, h1).unwrap();

        let (ct2, h2) = bob.encrypt_message(b"Hello Alice");
        alice.decrypt_message(&ct2, h2).unwrap();

        // Serialize both states
        let alice_bytes = alice.as_bytes();
        let bob_bytes = bob.as_bytes();

        // Deserialize
        let mut alice_restored: RatchetState = RatchetState::from_bytes(&alice_bytes).unwrap();
        let mut bob_restored: RatchetState = RatchetState::from_bytes(&bob_bytes).unwrap();

        // Continue the conversation with restored states
        let (ct3, h3) = alice_restored.encrypt_message(b"Message after restore");
        let pt3 = bob_restored.decrypt_message(&ct3, h3).unwrap();
        assert_eq!(pt3, b"Message after restore");

        let (ct4, h4) = bob_restored.encrypt_message(b"Reply after restore");
        let pt4 = alice_restored.decrypt_message(&ct4, h4).unwrap();
        assert_eq!(pt4, b"Reply after restore");
    }

    #[test]
    fn test_serialization_version_check() {
        let (alice, _, _) = setup_alice_bob();
        let mut bytes = alice.as_bytes();

        // Tamper with version byte
        bytes[0] = 0xFF;

        let result = RatchetState::<DefaultDomain>::from_bytes(&bytes);
        assert!(matches!(result, Err(RatchetError::DeserializationFailed)));
    }

    #[test]
    fn test_serialization_truncated_data() {
        let (alice, _, _) = setup_alice_bob();
        let bytes = alice.as_bytes();

        // Truncate the data
        let truncated = &bytes[..10];

        let result = RatchetState::<DefaultDomain>::from_bytes(truncated);
        assert!(matches!(result, Err(RatchetError::DeserializationFailed)));
    }

    #[test]
    fn test_serialization_size_efficiency() {
        let (alice, _, _) = setup_alice_bob();
        let bytes = alice.as_bytes();

        // Minimum size: version(1) + root_key(32) + sending_flag(1) + sending(32) +
        // receiving_flag(1) + dh_self(32) + dh_remote_flag(1) + dh_remote(32) +
        // counters(12) + skipped_count(4) = 148 bytes for sender with no skipped keys
        assert!(bytes.len() < 200, "Serialized size should be compact");

        // Verify version byte
        assert_eq!(bytes[0], 1, "Version should be 1");
    }

    #[test]
    fn test_skipped_keys_export() {
        let (mut alice, mut bob, _) = setup_alice_bob();

        // Initially no skipped keys
        assert!(bob.skipped_keys().is_empty());

        // Alice sends 4 messages
        let mut encrypted = vec![];
        for i in 0..4 {
            let msg = format!("Message {}", i).into_bytes();
            let (ct, h) = alice.encrypt_message(&msg);
            encrypted.push((ct, h, msg));
        }

        // Bob receives message 0 first
        bob.decrypt_message(&encrypted[0].0, encrypted[0].1.clone())
            .unwrap();
        assert!(bob.skipped_keys().is_empty());

        // Bob receives message 3, skipping 1 and 2
        bob.decrypt_message(&encrypted[3].0, encrypted[3].1.clone())
            .unwrap();

        // Now we should have 2 skipped keys (for messages 1 and 2)
        let skipped = bob.skipped_keys();
        assert_eq!(skipped.len(), 2);

        // Verify the skipped keys have the expected message numbers
        let msg_nums: Vec<u32> = skipped.iter().map(|sk| sk.msg_num).collect();
        assert!(msg_nums.contains(&1));
        assert!(msg_nums.contains(&2));

        // Verify each skipped key has valid data
        for sk in &skipped {
            assert_eq!(sk.public_key.len(), 32);
            assert_eq!(sk.message_key.len(), 32);
        }

        // Now decrypt message 1 using the skipped key
        bob.decrypt_message(&encrypted[1].0, encrypted[1].1.clone())
            .unwrap();

        // Should only have 1 skipped key left (for message 2)
        let skipped_after = bob.skipped_keys();
        assert_eq!(skipped_after.len(), 1);
        assert_eq!(skipped_after[0].msg_num, 2);
    }
}
