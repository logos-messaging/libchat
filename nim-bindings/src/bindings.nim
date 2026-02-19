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
  CreateIntroResult* = object
    error_code*: int32
    intro_bytes*: VecUint8

  ## Result structure for send_content
  ## error_code is 0 on success, negative on error (see ErrorCode)
  SendContentResult* = object
    error_code*: int32
    payloads*: VecPayload

  ## Result structure for handle_payload
  ## error_code is 0 on success, negative on error (see ErrorCode)
  HandlePayloadResult* = object
    error_code*: int32
    convo_id*: ReprCString
    content*: VecUint8
    is_new_convo*: bool

  ## Result from create_new_private_convo
  ## error_code is 0 on success, negative on error (see ErrorCode)
  NewConvoResult* = object
    error_code*: int32
    convo_id*: ReprCString
    payloads*: VecPayload

# FFI function imports

## Creates a new libchat Context
## Returns: Opaque handle to the context. Must be freed with destroy_context()
proc create_context*(name: ReprCString): ContextHandle {.importc, dynlib: CONVERSATIONS_LIB.}

## Returns the friendly name of the context's identity
## The result must be freed by the caller (repr_c::String ownership transfers)
proc get_friendly_name*(ctx: ContextHandle): ReprCString {.importc, dynlib: CONVERSATIONS_LIB.}

## Destroys a context and frees its memory
## - handle must be a valid pointer from create_context()
## - handle must not be used after this call
proc destroy_context*(ctx: ContextHandle) {.importc, dynlib: CONVERSATIONS_LIB.}

## Creates an intro bundle for sharing with other users
## Returns: CreateIntroResult struct - check error_code field (0 = success, negative = error)
## The result must be freed with destroy_intro_result()
proc create_intro_bundle*(
  ctx: ContextHandle,
): CreateIntroResult {.importc, dynlib: CONVERSATIONS_LIB.}

## Creates a new private conversation
## Returns: NewConvoResult struct - check error_code field (0 = success, negative = error)
## The result must be freed with destroy_convo_result()
proc create_new_private_convo*(
  ctx: ContextHandle,
  bundle: SliceUint8,
  content: SliceUint8,
): NewConvoResult {.importc, dynlib: CONVERSATIONS_LIB.}

## Sends content to an existing conversation
## Returns: SendContentResult struct - check error_code field (0 = success, negative = error)
## The result must be freed with destroy_send_content_result()
proc send_content*(
  ctx: ContextHandle,
  convo_id: ReprCString,
  content: SliceUint8,
): SendContentResult {.importc, dynlib: CONVERSATIONS_LIB.}

## Handles an incoming payload
## Returns: HandlePayloadResult struct - check error_code field (0 = success, negative = error)
## This call does not always generate content. If content is zero bytes long then there
## is no data, and the convo_id should be ignored.
## The result must be freed with destroy_handle_payload_result()
proc handle_payload*(
  ctx: ContextHandle,
  payload: SliceUint8,
): HandlePayloadResult {.importc, dynlib: CONVERSATIONS_LIB.}

## Free the result from create_intro_bundle
proc destroy_intro_result*(result: CreateIntroResult) {.importc, dynlib: CONVERSATIONS_LIB.}

## Free the result from create_new_private_convo
proc destroy_convo_result*(result: NewConvoResult) {.importc, dynlib: CONVERSATIONS_LIB.}

## Free the result from send_content
proc destroy_send_content_result*(result: SendContentResult) {.importc, dynlib: CONVERSATIONS_LIB.}

## Free the result from handle_payload
proc destroy_handle_payload_result*(result: HandlePayloadResult) {.importc, dynlib: CONVERSATIONS_LIB.}

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

## Create a ReprCString from a Nim string for passing to FFI functions.
## WARNING: The returned ReprCString borrows from the input string.
## The input string must remain valid for the duration of the FFI call.
## cap is set to 0 to prevent Rust from attempting to deallocate Nim memory.
proc toReprCString*(s: string): ReprCString =
  if s.len == 0:
    ReprCString(`ptr`: nil, len: 0, cap: 0)
  else:
    ReprCString(`ptr`: cast[ptr char](unsafeAddr s[0]), len: csize_t(s.len), cap: 0)

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

## Iterator for VecPayload
iterator items*(v: VecPayload): Payload =
  for i in 0 ..< v.len:
    yield v[int(i)]

## Convert a string to seq[byte]
proc toBytes*(s: string): seq[byte] =
  if s.len == 0:
    return @[]
  result = newSeq[byte](s.len)
  copyMem(addr result[0], unsafeAddr s[0], s.len)
