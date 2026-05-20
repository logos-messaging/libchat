use std::sync::{Mutex, mpsc};

use libchat::AddressedEnvelope;
use logos_chat::{DeliveryService, drain_inbound};

/// C callback invoked for each outbound envelope. Return 0 or positive on success, negative on
/// error. `addr_ptr/addr_len` is the delivery address; `data_ptr/data_len` is the encrypted
/// payload. Both pointers are borrowed for the duration of the call only; the callee must not
/// retain or free them.
pub type DeliverFn = Option<
    unsafe extern "C" fn(
        addr_ptr: *const u8,
        addr_len: usize,
        data_ptr: *const u8,
        data_len: usize,
    ) -> i32,
>;

/// `DeliveryService` for FFI consumers. Outbound publishes invoke the C
/// `DeliverFn` callback; inbound payloads are fed through a `Sender<Vec<u8>>`
/// returned at construction.
#[derive(Debug)]
pub struct CDelivery {
    callback: DeliverFn,
    inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl CDelivery {
    /// Returns the delivery together with the `Sender` that feeds its
    /// inbound side.
    pub fn new(callback: DeliverFn) -> (Self, mpsc::Sender<Vec<u8>>) {
        let (tx, rx) = mpsc::channel();
        let delivery = Self {
            callback,
            inbound: Mutex::new(rx),
        };
        (delivery, tx)
    }
}

impl DeliveryService for CDelivery {
    type Error = i32;

    fn publish(&self, envelope: AddressedEnvelope) -> Result<(), i32> {
        let cb = self.callback.expect("callback must be non-null");
        let addr = envelope.delivery_address.as_bytes();
        let data = envelope.data.as_slice();
        let rc = unsafe { cb(addr.as_ptr(), addr.len(), data.as_ptr(), data.len()) };
        if rc < 0 { Err(rc) } else { Ok(()) }
    }

    fn subscribe(&self, _delivery_address: &str) -> Result<(), Self::Error> {
        // TODO: (P1) CDelivery does not support delivery_address filtering.
        Ok(())
    }

    fn pull(&self) -> Vec<Vec<u8>> {
        drain_inbound(&self.inbound)
    }
}
