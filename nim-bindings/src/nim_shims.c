/* nim_shims.c — bridges Nim's calling convention to the standard C ABI.
 *
 * Nim transforms functions returning large structs (> register size) into
 * void functions with an explicit out-pointer appended as the last argument.
 * It also transforms large struct parameters (> ~24 bytes) into pointers.
 * These transformations do not match the x86-64 SysV hidden-return-pointer
 * convention (RDI) or ARM64 aapcs64 (X8), causing crashes.
 *
 * Each nim_* wrapper has a Nim-compatible signature. The C compiler handles
 * the correct hidden-pointer and stack-copy conventions when calling the
 * underlying Rust-exported functions.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef void* ContextHandle;

/* Matches c_slice::Ref<'_, u8> — 16 bytes, passed in registers */
typedef struct { const uint8_t* ptr; size_t len; } SliceRefU8;

/* Matches repr_c::Vec<u8> — 24 bytes */
typedef struct { uint8_t* ptr; size_t len; size_t cap; } VecU8;

/* Matches repr_c::String — 24 bytes */
typedef struct { char* ptr; size_t len; size_t cap; } ReprCString;

/* Matches FFI Payload — 48 bytes */
typedef struct { ReprCString address; VecU8 data; } Payload;

/* Matches repr_c::Vec<Payload> — 24 bytes */
typedef struct { Payload* ptr; size_t len; size_t cap; } VecPayload;

/* 32 bytes — Nim transforms: parameter → ptr, return → out-ptr at end */
typedef struct { int32_t error_code; VecU8 intro_bytes; } CreateIntroResult;

/* 56 bytes */
typedef struct { int32_t error_code; ReprCString convo_id; VecPayload payloads; } NewConvoResult;

/* 32 bytes */
typedef struct { int32_t error_code; VecPayload payloads; } SendContentResult;

/* 64 bytes */
typedef struct {
    int32_t error_code; ReprCString convo_id; VecU8 content; bool is_new_convo;
} HandlePayloadResult;

/* Forward declarations — Rust-exported functions, standard C ABI */
extern CreateIntroResult   create_intro_bundle(ContextHandle ctx);
extern NewConvoResult      create_new_private_convo(ContextHandle ctx, SliceRefU8 bundle, SliceRefU8 content);
extern SendContentResult   send_content(ContextHandle ctx, ReprCString convo_id, SliceRefU8 content);
extern HandlePayloadResult handle_payload(ContextHandle ctx, SliceRefU8 payload);
extern ReprCString         installation_name(ContextHandle ctx);
extern void destroy_intro_result(CreateIntroResult* result);       /* *mut T */
extern void destroy_convo_result(NewConvoResult* result);
extern void destroy_send_content_result(SendContentResult* result);
extern void destroy_handle_payload_result(HandlePayloadResult* result);

/* Return-value wrappers: C compiler inserts correct hidden-pointer per platform */
void nim_create_intro_bundle(ContextHandle ctx, CreateIntroResult* out) {
    *out = create_intro_bundle(ctx);
}
void nim_create_new_private_convo(ContextHandle ctx, SliceRefU8 bundle, SliceRefU8 content, NewConvoResult* out) {
    *out = create_new_private_convo(ctx, bundle, content);
}
void nim_send_content(ContextHandle ctx, ReprCString convo_id, SliceRefU8 content, SendContentResult* out) {
    *out = send_content(ctx, convo_id, content);
}
void nim_handle_payload(ContextHandle ctx, SliceRefU8 payload, HandlePayloadResult* out) {
    *out = handle_payload(ctx, payload);
}
void nim_installation_name(ContextHandle ctx, ReprCString* out) {
    *out = installation_name(ctx);
}

/* Destroy wrappers: Nim passes pointer (for > 24-byte params); forward to Rust *mut T */
void nim_destroy_intro_result(CreateIntroResult* result) {
    destroy_intro_result(result);
}
void nim_destroy_convo_result(NewConvoResult* result) {
    destroy_convo_result(result);
}
void nim_destroy_send_content_result(SendContentResult* result) {
    destroy_send_content_result(result);
}
void nim_destroy_handle_payload_result(HandlePayloadResult* result) {
    destroy_handle_payload_result(result);
}
