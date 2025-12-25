use x25519_dalek::PublicKey;

use crate::{
    dhkey::DhKeyPair,
    encryption::{decrypt, encrypt},
    kdf::{kdf_chain, kdf_root},
};

pub struct RatchetState {
    pub root_key: [u8; 32],

    pub sending_chain: Option<[u8; 32]>,
    pub receiving_chain: Option<[u8; 32]>,

    pub dh_self: DhKeyPair,
    pub dh_remote: Option<PublicKey>,
}

#[derive(Clone)]
pub struct Header {
    pub dh_pub: PublicKey,
}

impl Header {
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.dh_pub.as_bytes()
    }
}

impl RatchetState {
    pub fn dh_ratchet_receive(&mut self, remote_pub: PublicKey) {
        let dh_out = self.dh_self.dh(&remote_pub);
        let (new_root, recv_chain) = kdf_root(&self.root_key, &dh_out);

        self.root_key = new_root;
        self.receiving_chain = Some(recv_chain);
        self.sending_chain = None; // 🔥 important
        self.dh_remote = Some(remote_pub);
    }

    pub fn dh_ratchet_send(&mut self) {
        let remote = self.dh_remote.expect("no remote DH key");

        self.dh_self = DhKeyPair::generate();
        let dh_out = self.dh_self.dh(&remote);
        let (new_root, send_chain) = kdf_root(&self.root_key, &dh_out);

        self.root_key = new_root;
        self.sending_chain = Some(send_chain);
    }
}

impl RatchetState {
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> (Vec<u8>, [u8; 12], Header) {
        if self.sending_chain.is_none() {
            self.dh_ratchet_send();
        }

        let chain = self.sending_chain.as_mut().unwrap();
        let (next_chain, message_key) = kdf_chain(chain);
        *chain = next_chain;

        let header = Header {
            dh_pub: self.dh_self.public,
        };
        // let aad = self.dh_self.public.as_bytes();
        let (ciphertext, nonce) = encrypt(&message_key, plaintext, header.as_bytes());
        (ciphertext, nonce, header)
    }
}

impl RatchetState {
    pub fn decrypt_message(
        &mut self,
        ciphertext: &[u8],
        nonce: &[u8; 12],
        header: Header,
    ) -> Vec<u8> {
        if self.dh_remote.as_ref() != Some(&header.dh_pub) {
            self.dh_ratchet_receive(header.dh_pub);
        }

        let chain = self.receiving_chain.as_mut().expect("no receiving chain");
        let (next_chain, message_key) = kdf_chain(chain);
        *chain = next_chain;

        decrypt(&message_key, ciphertext, nonce, header.as_bytes())
    }
}
