import std/[sequtils, strutils]
import results

import bindings

# type 
#   LibChatResults[T] = Result[T, string]

type
  LibChat* = object
    handle: ContextHandle
    buffer_size: int

  PayloadResult* = object
    address*: string
    data*: seq[uint8]

proc newConversationsContext*(): LibChat =
  ## Create a new conversations context
  result.handle = create_context()
  if result.handle.isNil:
    raise newException(IOError, "Failed to create context")

proc destroy*(ctx: var LibChat) =
  ## Destroy the context and free resources
  if not ctx.handle.isNil:
    destroy_context(ctx.handle)
    ctx.handle = nil

proc getBuffer*(ctx: LibChat): seq[byte] =
  newSeq[byte](ctx.buffer_size)

proc sendContent*(ctx: LibChat, conversationId: string, content: openArray[uint8]): seq[PayloadResult] =
  ## Send content and get back payloads to deliver
  const
    maxPayloads = 10
    payloadMaxLen = 4096
    addrMaxLen = 256

  # Allocate buffers for payload data
  var payloadBuffers: array[maxPayloads, array[payloadMaxLen, uint8]]
  var payloadPtrs: array[maxPayloads, ptr uint8]
  for i in 0..<maxPayloads:
    payloadPtrs[i] = addr payloadBuffers[i][0]

  # Allocate buffers for addresses
  var addrBuffers: array[maxPayloads, array[addrMaxLen, char]]
  var addrPtrs: array[maxPayloads, ptr cchar]
  for i in 0..<maxPayloads:
    addrPtrs[i] = addr addrBuffers[i][0]

  var actualLengths: array[maxPayloads, csize_t]
  var maxLen: csize_t = payloadMaxLen

  let contentPtr = if content.len > 0: unsafeAddr content[0] else: nil

  let numPayloads = generate_payload(
    ctx.handle,
    conversationId.cstring,
    contentPtr,
    content.len.csize_t,
    maxPayloads.csize_t,
    addr addrPtrs[0],
    addrMaxLen.csize_t,
    addr payloadPtrs[0],
    addr maxLen,
    addr actualLengths[0]
  )

  if numPayloads < 0:
    case numPayloads:
    of ErrBadPtr:
      raise newException(ValueError, "Bad pointer passed to generate_payload")
    of ErrBadConvoId:
      raise newException(ValueError, "Bad conversation ID: " & conversationId)
    else:
      raise newException(IOError, "Unknown error: " & $numPayloads)

  result = @[]
  for i in 0..<numPayloads:
    var payload = PayloadResult()

    # Extract address (null-terminated string)
    payload.address = $cast[cstring](addr addrBuffers[i][0])

    # Extract payload data
    let dataLen = actualLengths[i].int
    payload.data = newSeq[uint8](dataLen)
    if dataLen > 0:
      copyMem(addr payload.data[0], addr payloadBuffers[i][0], dataLen)

    result.add(payload)

proc setBufferSize*(ctx: var LibChat, buffer_size: uint32) =
  if ctx.handle != nil:
    # Update local value
    ctx.buffer_size = buffer_size.int

    # Notify libchat what size buffers will be provided
    bindings.set_buffer_size(ctx.handle, buffer_size)

proc createIntroductionBundle*( ctx: LibChat) : Result[string,string] =
  if ctx.handle != nil:

    var buffer = ctx.getBuffer()
    let buf = cast[ptr UncheckedArray[byte]](addr buffer[0])
    let len = create_intro_bundle(ctx.handle, buf)

    if len < 0:
      return err("Failed to create intro bundle")

    buffer.setLen(len)
    return ok(cast[string](buffer))

proc createNewPrivateConvo*(ctx: LibChat, bundle: string, content: string): Result[(ConvoHandle, seq[byte]), string] =
  if ctx.handle == nil:
    return err("Context handle is nil")

  # Convert strings to byte pointers
  let bundlePtr = if bundle.len > 0: cast[ptr uint8](unsafeAddr bundle[0]) else: return err("bundle is zero length")
  let contentPtr = if content.len > 0: cast[ptr uint8](unsafeAddr content[0]) else: return err("content is zero length")

  # Output buffers
  var convoHandle: ConvoHandle
  var messageOut = ctx.getBuffer()
  let messageOutPtr = cast[ptr UncheckedArray[byte]](addr messageOut[0])

  let result_code = bindings.create_new_private_convo(
    ctx.handle,
    bundlePtr,
    bundle.len.csize_t,
    contentPtr,
    content.len.csize_t,
    cast[ptr uint32](addr convoHandle),
    messageOutPtr
  )

  if result_code < 0:
    return err("Failed to create private convo: " & $result_code)

  # result_code is bytes written to messageOut
  messageOut.setLen(result_code)

  return ok((convoHandle, messageOut))


proc `=destroy`(x: var LibChat) =
  # Automatically free handle when the destructor is called
  if x.handle != nil:
    x.destroy()
