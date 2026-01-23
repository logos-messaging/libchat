use core::ffi::c_char;
use std::{ffi::CStr, slice};

// Must only contain negative values, values cannot be changed once set.
#[repr(i32)]
pub enum ErrorCode {
    BadPtr = -1,
    BadConvoId = -2,
    BadIntro = -3,
    NotImplemented = -4,
    BufferExceeded = -5,
}

use crate::context::{Context, Introduction};

pub type ContextHandle = *mut Context;

/// Creates a new libchat Ctx
///
/// # Returns
/// Opaque handle to the store. Must be freed with conversation_store_destroy()
#[unsafe(no_mangle)]
pub extern "C" fn create_context() -> ContextHandle {
    let store = Box::new(Context::new());
    Box::into_raw(store) // Leak the box, return raw pointer
}

/// Destroys a conversation store and frees its memory
///
/// # Safety
/// - handle must be a valid pointer from conversation_store_create()
/// - handle must not be used after this call
/// - handle must not be freed twice
#[unsafe(no_mangle)]
pub unsafe extern "C" fn destroy_context(handle: ContextHandle) {
    if !handle.is_null() {
        unsafe {
            let _ = Box::from_raw(handle); // Reconstruct box and drop it
        }
    }
}

/// Notify Context which size of buffers will be provided
///
/// Operations which would exceed the buffer size will return an Overflow error
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn set_buffer_size(handle: ContextHandle, buf_size: usize) {
    if !handle.is_null() {
        unsafe {
            let ctx = &mut *handle;
            ctx.set_buffer_size(buf_size);
        }
    }
}

/// Encrypts/encodes content into payloads.
/// There may be multiple payloads generated from a single content.
///
/// # Returns
/// Returns the number of payloads created.
///
/// # Errors
/// Negative numbers symbolize an error has occured. See `ErrorCode`
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn generate_payload(
    // Input: Context Handle
    handle: ContextHandle,
    // Input: Conversation_id
    conversation_id: *const c_char,
    // Input: Content array
    content: *const u8,
    content_len: usize,

    max_payload_count: usize,
    // Output: Addresses
    addrs: *const *mut c_char,
    addr_max_len: usize,

    // Output: Frame data
    payload_buffer_ptrs: *const *mut u8,
    payload_buffer_max_len: *const usize, //Single Value

    // Output: Array - Number of bytes written to each payload
    output_actual_lengths: *mut usize,
) -> i32 {
    if handle.is_null() || content.is_null() || payload_buffer_ptrs.is_null() || addrs.is_null() {
        return ErrorCode::BadPtr as i32;
    }

    unsafe {
        let ctx = &mut *handle;
        let content_slice = slice::from_raw_parts(content, content_len);
        let payload_ptrs_slice = slice::from_raw_parts(payload_buffer_ptrs, max_payload_count);
        let payload_max_len = if !payload_buffer_max_len.is_null() {
            *payload_buffer_max_len
        } else {
            return ErrorCode::BadPtr as i32;
        };
        let addrs_slice = slice::from_raw_parts(addrs, max_payload_count);
        let actual_lengths_slice =
            slice::from_raw_parts_mut(output_actual_lengths, max_payload_count);

        let c_str = CStr::from_ptr(conversation_id);
        let id_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => return ErrorCode::BadConvoId as i32,
        };

        // Call ctx.send_content to get payloads
        let payloads = ctx.send_content(id_str, content_slice);

        // Check if we have enough output buffers
        if payloads.len() > max_payload_count {
            return ErrorCode::BadPtr as i32; // Not enough output buffers
        }

        // Write each payload to the output buffers
        for (i, payload) in payloads.iter().enumerate() {
            let payload_ptr = payload_ptrs_slice[i];
            let addr_ptr = addrs_slice[i];

            // Write payload data
            if !payload_ptr.is_null() {
                let payload_buf = slice::from_raw_parts_mut(payload_ptr, payload_max_len);
                let copy_len = payload.data.len().min(payload_max_len);
                payload_buf[..copy_len].copy_from_slice(&payload.data[..copy_len]);
                actual_lengths_slice[i] = copy_len;
            } else {
                return ErrorCode::BadPtr as i32;
            }

            // Write delivery address
            if !addr_ptr.is_null() {
                let addr_bytes = payload.delivery_address.as_bytes();
                let addr_buf = slice::from_raw_parts_mut(addr_ptr as *mut u8, addr_max_len);
                let copy_len = addr_bytes.len().min(addr_max_len - 1);
                addr_buf[..copy_len].copy_from_slice(&addr_bytes[..copy_len]);
                addr_buf[copy_len] = 0; // Null-terminate
            } else {
                return ErrorCode::BadPtr as i32;
            }
        }

        payloads.len() as i32
    }
}

/// Decrypts/decodes payloads into content.
/// A payload may return 1 or 0 contents.
///
/// # Returns
/// Returns the number of bytes written to content
///
/// # Errors
/// Negative numbers symbolize an error has occured. See `ErrorCode`
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn handle_payload(
    // Input: Context handle
    handle: ContextHandle,
    // Input: Payload data
    payload_data: *const u8,
    payload_len: usize,

    // Output: Content
    content: *mut u8,
    content_max_len: usize,
) -> i32 {
    if handle.is_null() || payload_data.is_null() || content.is_null() {
        return ErrorCode::BadPtr as i32;
    }

    unsafe {
        let ctx = &mut *handle;
        let payload_slice = slice::from_raw_parts(payload_data, payload_len);
        let content_buf = slice::from_raw_parts_mut(content, content_max_len);

        // Call ctx.handle_payload to decode the payload
        let contents = ctx.handle_payload(payload_slice);

        if let Some(content_data) = contents {
            let copy_len = content_data.data.len().min(content_max_len);
            content_buf[..copy_len].copy_from_slice(&content_data.data[..copy_len]);
            copy_len as i32
        } else {
            0 // No content produced
        }
    }
}

/// Creates an intro bundle for sharing with other users
///
/// # Returns
/// Returns the number of bytes written to the output buffer
///
/// # Errors
/// Negative numbers symbolize an error has occured. See `ErrorCode`
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn create_intro_bundle(
    // Input: Context handle
    handle: ContextHandle,
    // Output: Bundle data
    bundle_out: *mut u8,
) -> i32 {
    if handle.is_null() || bundle_out.is_null() {
        return ErrorCode::BadPtr as i32;
    }

    unsafe {
        let ctx = &mut *handle;
        let bundle_max_len = ctx.buffer_size();
        let bundle_buf = slice::from_raw_parts_mut(bundle_out, bundle_max_len);

        // TODO: Change function to accept a mut byte slice to reduce copies
        match ctx.create_intro_bundle() {
            Ok(bundle_data) => {
                let copy_len = bundle_data.len().min(bundle_max_len);
                bundle_buf[..copy_len].copy_from_slice(&bundle_data[..copy_len]);
                copy_len as i32
            }
            Err(_) => ErrorCode::BadPtr as i32, // TODO: Add appropriate error code for bundle creation failure
        }
    }
}

/// Creates an intro bundle for sharing with other users
///
/// # Returns
/// Returns the number of bytes written to the output buffer
///
/// # Errors
/// Negative numbers symbolize an error has occured. See `ErrorCode`
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn create_new_private_convo(
    // Input: Context handle
    handle: ContextHandle,
    bundle: *const u8,
    bundle_size: usize,
    content: *const u8,
    content_size: usize,
    // Output: Bundle data
    convo_id_out: *mut u32,
    payload_out: *mut u8,
) -> i32 {
    if handle.is_null() || payload_out.is_null() {
        return ErrorCode::BadPtr as i32;
    }

    unsafe {
        let ctx = &mut *handle;
        let buffer_max_len = ctx.buffer_size();

        // Convert input bundle ptr to Introduction
        let bundle_slice = slice::from_raw_parts(bundle, bundle_size);
        let s = String::from_utf8_lossy(bundle_slice).into_owned();
        let Ok(intro) = Introduction::try_from(s) else {
            return ErrorCode::BadIntro as i32;
        };

        let payload_buf = slice::from_raw_parts_mut(payload_out, buffer_max_len);

        // Convert input content to String
        let msg_slice = std::slice::from_raw_parts(content, content_size);
        let msg = String::from_utf8_lossy(msg_slice).into_owned();

        // Create conversation
        let (convo_handle, payloads) = ctx.create_private_convo(&intro, msg);

        // TODO: Handle potentially multiple payloads
        if payloads.len() > 1 {
            return ErrorCode::NotImplemented as i32;
        }

        let mut bytes_written = 0 as i32;

        // Copy payload bytes to output
        if let Some(payload) = payloads.get(0) {
            let copy_len = payload.data.len();
            if copy_len > buffer_max_len {
                return ErrorCode::BufferExceeded as i32;
            }

            payload_buf[..copy_len].copy_from_slice(&payload.data[..copy_len]);
            bytes_written = copy_len as i32;
        }

        // Write Convo ID to output;
        *convo_id_out = convo_handle;

        return bytes_written;
    }
}
