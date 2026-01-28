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
proc newConversationsContext*(): LibChat =

  result.handle = create_context()
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
proc createIntroductionBundle*(ctx: LibChat): Result[string, string] =
  if ctx.handle == nil:
    return err("Context handle is nil")

  var buffer = ctx.getBuffer()
  var slice = buffer.toSlice()
  let len = create_intro_bundle(ctx.handle, slice)

  if len < 0:
    return err("Failed to create intro bundle: " & $len)

  buffer.setLen(len)
  return ok(cast[string](buffer))

## Create a Private Convo
proc createNewPrivateConvo*(ctx: LibChat, bundle: string, content: string): Result[(ConvoHandle, seq[PayloadResult]), string] =
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

  let convoId = res.convo_id

  # Free the result
  destroy_convo_result(res)

  return ok((convoId, payloads))


proc `=destroy`(x: var LibChat) =
  # Automatically free handle when the destructor is called
  if x.handle != nil:
    x.destroy()
