use crossbeam_channel::Receiver;
use libchat::AddressedEnvelope;
use logos_chat::{DeliveryService, Transport};

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

#[derive(Debug)]
pub struct CDelivery {
    pub callback: DeliverFn,
    inbound_rx: Option<Receiver<Vec<u8>>>,
}

impl CDelivery {
    pub fn new(callback: DeliverFn, inbound: Receiver<Vec<u8>>) -> Self {
        Self {
            callback,
            inbound_rx: Some(inbound),
        }
    }
}

impl DeliveryService for CDelivery {
    type Error = i32;

    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), i32> {
        let cb = self.callback.expect("callback must be non-null");
        let addr = envelope.delivery_address.as_bytes();
        let data = envelope.data.as_slice();
        let rc = unsafe { cb(addr.as_ptr(), addr.len(), data.as_ptr(), data.len()) };
        if rc < 0 { Err(rc) } else { Ok(()) }
    }

    fn subscribe(&mut self, _delivery_address: &str) -> Result<(), Self::Error> {
        // TODO: (P1) CDelivery does not support delivery_address filtering
        Ok(())
    }
}

impl Transport for CDelivery {
    fn inbound(&mut self) -> Receiver<Vec<u8>> {
        self.inbound_rx
            .take()
            .expect("CDelivery::inbound called more than once")
    }
}
