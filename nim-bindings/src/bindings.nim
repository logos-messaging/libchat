# Nim FFI bindings for libchat conversations library

import std/[os]

# Dynamic library path resolution
# Can be overridden at compile time with -d:CONVERSATIONS_LIB:"path/to/lib"
# Or at runtime via LIBCHAT_LIB environment variable
when defined(macosx):
  const DEFAULT_LIB_NAME = "liblogos_chat.dylib"
elif defined(linux):
  const DEFAULT_LIB_NAME = "liblogos_chat.so"
elif defined(windows):
  const DEFAULT_LIB_NAME = "logos_chat.dll"
else:
  const DEFAULT_LIB_NAME = "logos_chat"

# Try to find the library relative to the source file location at compile time
const
  thisDir = currentSourcePath().parentDir()
  projectRoot = thisDir.parentDir().parentDir()
  releaseLibPath = projectRoot / "target" / "release" / DEFAULT_LIB_NAME
  debugLibPath = projectRoot / "target" / "debug" / DEFAULT_LIB_NAME

# Default to release path, can be overridden with -d:CONVERSATIONS_LIB:"..."
const CONVERSATIONS_LIB* {.strdefine.} = releaseLibPath

# Error codes (must match Rust ErrorCode enum)
const
  ErrBadPtr* = -1'i32
  ErrBadConvoId* = -2'i32

# Opaque handle type for Context
type ContextHandle* = pointer
type ConvoHandle* = uint32

# FFI function imports

## Creates a new libchat Context
## Returns: Opaque handle to the context. Must be freed with destroy_context()
proc create_context*(): ContextHandle {.importc, dynlib: CONVERSATIONS_LIB.}

## Destroys a context and frees its memory
## - handle must be a valid pointer from create_context()
## - handle must not be used after this call
proc destroy_context*(handle: ContextHandle) {.importc, dynlib: CONVERSATIONS_LIB.}


## Encrypts/encodes content into payloads.
## Returns: Number of payloads created, or negative error code
proc generate_payload*(
  handle: ContextHandle,
  conversation_id: cstring,
  content: ptr uint8,
  content_len: csize_t,
  max_payload_count: csize_t,
  addrs: ptr ptr cchar,
  addr_max_len: csize_t,
  payload_buffer_ptrs: ptr ptr uint8,
  payload_buffer_max_len: ptr csize_t,
  output_actual_lengths: ptr csize_t
): int32 {.importc, dynlib: CONVERSATIONS_LIB.}


## Decrypts/decodes payloads into content.
## Returns: Number of bytes written to content, or negative error code
proc handle_payload*(
  handle: ContextHandle,
  payload_data: ptr uint8,
  payload_len: csize_t,
  content: ptr uint8,
  content_max_len: csize_t
): int32 {.importc, dynlib: CONVERSATIONS_LIB.}

proc set_buffer_size*(
  handle: ContextHandle,
  buf_size: uint32,
) {.importc, dynlib: CONVERSATIONS_LIB.}

## Fills provided buffer with a introduction bundle for intializing conversations
proc create_intro_bundle*(
  handle: ContextHandle,
  bundle_out: ptr UncheckedArray[byte],
): int32 {.importc, dynlib: CONVERSATIONS_LIB.}
  
## Fills provided buffer with a introduction bundle for intializing conversations
proc create_new_private_convo*(
  handle: ContextHandle,
  bundle: ptr uint8,
  bundle_size: csize_t,
  content: ptr uint8,
  content_size: csize_t,
  convo_id: ptr uint32,
  payload_out: ptr UncheckedArray[byte],
): int32 {.importc, dynlib: CONVERSATIONS_LIB.}

