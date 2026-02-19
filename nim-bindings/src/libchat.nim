import std/options
import std/sequtils
import results
import bindings

type
  LibChat* = object
    handle: ContextHandle
    buffer_size: int

  PayloadResult* = object
    address*: string
    data*: seq[uint8]

## Create a new conversations context
proc newConversationsContext*(name: string): LibChat =

  result.handle = create_context(name.toReprCString)
  result.buffer_size = 256
  if result.handle.isNil:
    raise newException(IOError, "Failed to create context")

## Destroy the context and free resources
proc destroy*(ctx: var LibChat) =

  if not ctx.handle.isNil:
    destroy_context(ctx.handle)
    ctx.handle = nil

## Helper proc to create buffer of sufficient size
proc getBuffer*(ctx: LibChat): seq[byte] =
  newSeq[byte](ctx.buffer_size)

## Generate a Introduction Bundle
proc createIntroductionBundle*(ctx: LibChat): Result[seq[byte], string] =
  if ctx.handle == nil:
    return err("Context handle is nil")

  let res = create_intro_bundle(ctx.handle)

  if res.error_code != ErrNone:
    result = err("Failed to create private convo: " & $res.error_code)
    destroy_intro_result(res)
    return

  return ok(res.intro_bytes.toSeq())

## Create a Private Convo
proc createNewPrivateConvo*(ctx: LibChat, bundle: seq[byte], content: seq[byte]): Result[(string, seq[PayloadResult]), string] =
  if ctx.handle == nil:
    return err("Context handle is nil")

  if bundle.len == 0:
    return err("bundle is zero length")
  if content.len == 0:
    return err("content is zero length")

  let res = bindings.create_new_private_convo(
    ctx.handle,
    bundle.toSlice(),
    content.toSlice()
  )

  if res.error_code != 0:
    result = err("Failed to create private convo: " & $res.error_code)
    destroy_convo_result(res)
    return

  # Convert payloads to Nim types
  var payloads = newSeq[PayloadResult](res.payloads.len)
  for i in 0 ..< res.payloads.len:
    let p = res.payloads[int(i)]
    payloads[int(i)] = PayloadResult(
      address: $p.address,
      data: p.data.toSeq()
    )

  let convoId = $res.convo_id

  # Free the result
  destroy_convo_result(res)

  return ok((convoId, payloads))

## Send content to an existing conversation
proc sendContent*(ctx: LibChat, convoId: string, content: seq[byte]): Result[seq[PayloadResult], string] =
  if ctx.handle == nil:
    return err("Context handle is nil")

  if content.len == 0:
    return err("content is zero length")

  let res = bindings.send_content(
    ctx.handle,
    convoId.toReprCString,
    content.toSlice()
  )

  if res.error_code != 0:
    result = err("Failed to send content: " & $res.error_code)
    destroy_send_content_result(res)
    return


  let payloads = res.payloads.toSeq().mapIt(PayloadResult(
    address: $it.address,
    data: it.data.toSeq()
  ))

  destroy_send_content_result(res)
  return ok(payloads)

type
  ContentResult* = object
    conversationId*: string
    data*: seq[uint8]
    isNewConvo*: bool

## Handle an incoming payload and decrypt content
proc handlePayload*(ctx: LibChat, payload: seq[byte]): Result[Option[ContentResult], string] =
  if ctx.handle == nil:
    return err("Context handle is nil")

  if payload.len == 0:
    return err("payload is zero length")

  var conversationIdBuf = newSeq[byte](ctx.buffer_size)
  var contentBuf = newSeq[byte](ctx.buffer_size)
  var conversationIdLen: uint32 = 0

  let res = bindings.handle_payload(
    ctx.handle,
    payload.toSlice(),
  )

  if res.error_code != ErrNone:
    return err("Failed to handle payload: " & $res.error_code)

  let content = res.content.toSeq()
  if content.len == 0:
    return ok(none(ContentResult))

  return ok(some(ContentResult(
    conversationId: $res.convo_id,
    data: content,
    isNewConvo: res.is_new_convo
  )))
