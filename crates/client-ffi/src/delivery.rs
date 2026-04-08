use client::DeliveryService;
use libchat::AddressedEnvelope;

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

pub struct CDelivery {
    pub callback: DeliverFn,
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
}
