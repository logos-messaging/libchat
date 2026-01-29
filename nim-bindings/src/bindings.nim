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
  ErrNone* = 0'i32
  ErrBadPtr* = -1'i32
  ErrBadConvoId* = -2'i32
  ErrBadIntro* = -3'i32
  ErrNotImplemented* = -4'i32
  ErrBufferExceeded* = -5'i32
  ErrUnknownError* = -6'i32

# Opaque handle type for Context
type ContextHandle* = pointer
type ConvoHandle* = uint32

type
  ## Slice for passing byte arrays to safer_ffi functions
  SliceUint8* = object
    `ptr`*: ptr uint8
    len*: csize_t

  ## Vector type returned by safer_ffi functions (must be freed)
  VecUint8* = object
    `ptr`*: ptr uint8
    len*: csize_t
    cap*: csize_t

  ## repr_c::String type from safer_ffi
  ReprCString* = object
    `ptr`*: ptr char
    len*: csize_t
    cap*: csize_t

  ## Payload structure for FFI (matches Rust Payload struct)
  Payload* = object
    address*: ReprCString
    data*: VecUint8

  ## Vector of Payloads returned by safer_ffi functions
  VecPayload* = object
    `ptr`*: ptr Payload
    len*: csize_t
    cap*: csize_t

  ## Result structure for create_intro_bundle
  ## error_code is 0 on success, negative on error (see ErrorCode)
  PayloadResult* = object
    error_code*: int32
    payloads*: VecPayload

  ## Result from create_new_private_convo
  ## error_code is 0 on success, negative on error (see ErrorCode)
  NewConvoResult* = object
    error_code*: int32
    convo_id*: uint32
    payloads*: VecPayload

# FFI function imports

## Creates a new libchat Context
## Returns: Opaque handle to the context. Must be freed with destroy_context()
proc create_context*(): ContextHandle {.importc, dynlib: CONVERSATIONS_LIB.}

## Destroys a context and frees its memory
## - handle must be a valid pointer from create_context()
## - handle must not be used after this call
proc destroy_context*(ctx: ContextHandle) {.importc, dynlib: CONVERSATIONS_LIB.}

## Creates an intro bundle for sharing with other users
## Returns: Number of bytes written to bundle_out, or negative error code
proc create_intro_bundle*(
  ctx: ContextHandle,
  bundle_out: SliceUint8,
): int32 {.importc, dynlib: CONVERSATIONS_LIB.}

## Creates a new private conversation
## Returns: NewConvoResult struct - check error_code field (0 = success, negative = error)
## The result must be freed with destroy_convo_result()
proc create_new_private_convo*(
  ctx: ContextHandle,
  bundle: SliceUint8,
  content: SliceUint8,
): NewConvoResult {.importc, dynlib: CONVERSATIONS_LIB.}

## Sends content to an existing conversation
## Returns: PayloadResult struct - check error_code field (0 = success, negative = error)
## The result must be freed with destroy_payload_result()
proc send_content*(
  ctx: ContextHandle,
  convo_handle: ConvoHandle,
  content: SliceUint8,
): PayloadResult {.importc, dynlib: CONVERSATIONS_LIB.}

## Handles an incoming payload and writes content to caller-provided buffers
## Returns: Number of bytes written to content_out on success (>= 0), negative error code on failure
## conversation_id_out_len is set to the number of bytes written to conversation_id_out
proc handle_payload*(
  ctx: ContextHandle,
  payload: SliceUint8,
  conversation_id_out: SliceUint8,
  conversation_id_out_len: ptr uint32,
  content_out: SliceUint8,
): int32 {.importc, dynlib: CONVERSATIONS_LIB.}

## Free the result from create_new_private_convo
proc destroy_convo_result*(result: NewConvoResult) {.importc, dynlib: CONVERSATIONS_LIB.}

## Free the PayloadResult
proc destroy_payload_result*(result: PayloadResult) {.importc, dynlib: CONVERSATIONS_LIB.}

# ============================================================================
# Helper functions
# ============================================================================

## Create a SliceRefUint8 from a string
proc toSlice*(s: string): SliceUint8 =
  if s.len == 0:
    SliceUint8(`ptr`: nil, len: 0)
  else:
    SliceUint8(`ptr`: cast[ptr uint8](unsafeAddr s[0]), len: csize_t(s.len))

## Create a SliceRefUint8 from a seq[byte]
proc toSlice*(s: seq[byte]): SliceUint8 =
  if s.len == 0:
    SliceUint8(`ptr`: nil, len: 0)
  else:
    SliceUint8(`ptr`: cast[ptr uint8](unsafeAddr s[0]), len: csize_t(s.len))

## Convert a ReprCString to a Nim string
proc `$`*(s: ReprCString): string =
  if s.ptr == nil or s.len == 0:
    return ""
  result = newString(s.len)
  copyMem(addr result[0], s.ptr, s.len)

## Convert a VecUint8 to a seq[byte]
proc toSeq*(v: VecUint8): seq[byte] =
  if v.ptr == nil or v.len == 0:
    return @[]
  result = newSeq[byte](v.len)
  copyMem(addr result[0], v.ptr, v.len)

## Access payloads from VecPayload
proc `[]`*(v: VecPayload, i: int): Payload =
  assert i >= 0 and csize_t(i) < v.len
  cast[ptr UncheckedArray[Payload]](v.ptr)[i]

## Get length of VecPayload
proc len*(v: VecPayload): int =
  int(v.len)
