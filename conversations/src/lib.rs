mod api;
mod context;
mod conversation;
mod errors;
mod inbox;

pub use api::*;

#[cfg(test)]
use conversation::{ConversationStore, GroupTestConvo, PrivateV1Convo};
use inbox::Inbox;

mod tests {

    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_ffi() {}

    #[test]
    fn test_process_and_write() {
        // Create Context
        let ctx = create_context();

        // Setup conversation_id
        let conv_id = CString::new("test_conversation_123").unwrap();

        // Setup content
        let content = b"Hello, World!";

        // Setup output buffers for addresses (labels)
        let addr_max_len = 256;
        let mut addr_buffer1: Vec<u8> = vec![0; addr_max_len];
        let mut addr_buffer2: Vec<u8> = vec![0; addr_max_len];

        let addr_ptrs: Vec<*mut i8> = vec![
            addr_buffer1.as_mut_ptr() as *mut i8,
            addr_buffer2.as_mut_ptr() as *mut i8,
        ];

        // Setup payload buffers
        let max_payload_count = 2;
        let payload_max_len = 1024;
        let mut payload1: Vec<u8> = vec![0; payload_max_len];
        let mut payload2: Vec<u8> = vec![0; payload_max_len];

        let payload_ptrs: Vec<*mut u8> = vec![payload1.as_mut_ptr(), payload2.as_mut_ptr()];

        let payload_max_lens: Vec<usize> = vec![payload_max_len, payload_max_len];
        let mut actual_lengths: Vec<usize> = vec![0; max_payload_count];

        // Call the FFI function
        let result = unsafe {
            generate_payload(
                ctx,
                conv_id.as_ptr(),
                content.as_ptr(),
                content.len(),
                max_payload_count,
                addr_ptrs.as_ptr(),
                addr_max_len,
                payload_ptrs.as_ptr(),
                payload_max_lens.as_ptr(),
                actual_lengths.as_mut_ptr(),
            )
        };

        // Verify results
        assert_eq!(result, 1, "Function should return 1 on success");

        // Check that the conversation ID was written to the first label buffer
        let written_addr = std::ffi::CStr::from_bytes_until_nul(&addr_buffer1)
            .unwrap()
            .to_str()
            .unwrap();

        assert_eq!(written_addr, "test_conversation_123");

        unsafe {
            destroy_context(ctx);
        }
    }

    #[test]
    fn test_process_and_write_null_ptr() {
        use std::ptr;
        // Create Context
        let ctx = create_context();

        let conv_id = CString::new("test").unwrap();
        let content = b"test";

        // Test with null content pointer
        let result = unsafe {
            generate_payload(
                ctx,
                conv_id.as_ptr(),
                ptr::null(),
                content.len(),
                1,
                ptr::null(),
                256,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
            )
        };

        unsafe {
            destroy_context(ctx);
        }

        assert_eq!(result, -1, "Should return ERR_BAD_PTR for null pointer");
    }

    #[test]
    fn convo_store_get() {
        let mut store: ConversationStore = ConversationStore::new();

        let new_convo = GroupTestConvo::new();
        let convo_id = store.insert(new_convo);

        let convo = store.get_mut(&convo_id).ok_or_else(|| 0);
        convo.unwrap();
    }

    #[test]
    fn multi_convo_example() {
        let mut store: ConversationStore = ConversationStore::new();

        let raya = Inbox::new("Raya");
        let saro = PrivateV1Convo::new();
        let pax = GroupTestConvo::new();

        store.insert(raya);
        store.insert(saro);
        let convo_id = store.insert(pax);

        for id in store.conversation_ids().collect::<Vec<_>>() {
            let a = store.get_mut(&id).unwrap();
            a.send_frame(b"test message").unwrap();
            println!("Conversation ID: {} :: {:?}", id, a);
        }

        for id in store.conversation_ids().collect::<Vec<_>>() {
            let a = store.get_mut(&id).unwrap();
            let _ = a.handle_frame(&[0x1, 0x2]);
        }

        println!("ID -> {}", store.get(&convo_id).unwrap().id());
    }
}
