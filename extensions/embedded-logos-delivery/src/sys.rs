//! Raw FFI declarations matching liblogosdelivery.h (trampoline pattern).
//!
//! No `#[link]` attribute — build.rs handles linking to liblogosdelivery.
#![allow(unused)]

use std::os::raw::{c_char, c_int, c_void};
use std::slice;

pub const RET_OK: i32 = 0;

pub type FFICallBack = unsafe extern "C" fn(c_int, *const c_char, usize, *const c_void);

unsafe extern "C" {
    pub fn logosdelivery_create_node(
        config_json: *const c_char,
        cb: FFICallBack,
        user_data: *const c_void,
    ) -> *mut c_void;

    pub fn logosdelivery_start_node(
        ctx: *mut c_void,
        cb: FFICallBack,
        user_data: *const c_void,
    ) -> c_int;

    pub fn logosdelivery_stop_node(
        ctx: *mut c_void,
        cb: FFICallBack,
        user_data: *const c_void,
    ) -> c_int;

    pub fn logosdelivery_destroy(
        ctx: *mut c_void,
        cb: FFICallBack,
        user_data: *const c_void,
    ) -> c_int;

    pub fn logosdelivery_subscribe(
        ctx: *mut c_void,
        cb: FFICallBack,
        user_data: *const c_void,
        content_topic: *const c_char,
    ) -> c_int;

    pub fn logosdelivery_unsubscribe(
        ctx: *mut c_void,
        cb: FFICallBack,
        user_data: *const c_void,
        content_topic: *const c_char,
    ) -> c_int;

    /// `message_json`: `{"contentTopic": "...", "payload": "<base64>", "ephemeral": false}`
    pub fn logosdelivery_send(
        ctx: *mut c_void,
        cb: FFICallBack,
        user_data: *const c_void,
        message_json: *const c_char,
    ) -> c_int;

    pub fn logosdelivery_set_event_callback(
        ctx: *mut c_void,
        cb: FFICallBack,
        user_data: *const c_void,
    );

    pub fn logosdelivery_get_node_info(
        ctx: *mut c_void,
        cb: FFICallBack,
        user_data: *const c_void,
        node_info_id: *const c_char,
    ) -> c_int;
}

// ── Trampoline ───────────────────────────────────────────────────────────────

pub unsafe extern "C" fn trampoline<C>(
    return_val: c_int,
    buffer: *const c_char,
    buffer_len: usize,
    data: *const c_void,
) where
    C: FnMut(i32, &str),
{
    if data.is_null() {
        return;
    }
    let closure = unsafe { &mut *(data as *mut C) };
    if buffer.is_null() || buffer_len == 0 {
        closure(return_val, "");
        return;
    }
    let bytes = unsafe { slice::from_raw_parts(buffer as *const u8, buffer_len) };
    let s = String::from_utf8_lossy(bytes);
    closure(return_val, &s);
}

pub fn get_trampoline<C>(_: &C) -> FFICallBack
where
    C: FnMut(i32, &str),
{
    trampoline::<C>
}
