# Comprehensive test for all FFI procs declared in bindings.nim.
#
# Design intent: By importing `bindings` directly and calling every importc
# proc at least once, the linker is forced to include ALL symbol references.
# This prevents link-time optimizations from stripping unused symbols and
# catches both link-time crashes (missing symbols) and runtime crashes
# (wrong ABI, segfaults on use).

import bindings

# ---------------------------------------------------------------------------
# Assertion helper
# ---------------------------------------------------------------------------

proc check(cond: bool, msg: string) =
  if not cond:
    echo "FAIL: ", msg
    quit(1)
  echo "OK:   ", msg

# ---------------------------------------------------------------------------
# Section 1: Helper proc coverage
# ---------------------------------------------------------------------------

proc testHelperProcs() =
  echo "\n--- testHelperProcs ---"

  # toSlice(string) — non-empty and empty branches
  let s = "hello"
  let sl = toSlice(s)
  check(sl.len == 5, "toSlice(string): correct len")
  check(sl.`ptr` != nil, "toSlice(non-empty string): non-nil ptr")

  let emptySl = toSlice("")
  check(emptySl.len == 0, "toSlice(empty string): len == 0")
  check(emptySl.`ptr` == nil, "toSlice(empty string): ptr == nil")

  # toSlice(seq[byte]) — non-empty and empty branches
  let b: seq[byte] = @[0x61'u8, 0x62'u8, 0x63'u8]
  let bSl = toSlice(b)
  check(bSl.len == 3, "toSlice(seq[byte]): correct len")
  check(bSl.`ptr` != nil, "toSlice(non-empty seq[byte]): non-nil ptr")

  let emptyBSl = toSlice(newSeq[byte](0))
  check(emptyBSl.len == 0, "toSlice(empty seq[byte]): len == 0")
  check(emptyBSl.`ptr` == nil, "toSlice(empty seq[byte]): ptr == nil")

  # toReprCString(string) and $(ReprCString) round-trip
  let name = "testname"
  let rcs = toReprCString(name)
  check(rcs.len == csize_t(name.len), "toReprCString: correct len")
  check(rcs.cap == 0, "toReprCString: cap == 0 (prevents Rust dealloc of Nim memory)")
  check(rcs.`ptr` != nil, "toReprCString: non-nil ptr")
  check($rcs == name, "$(ReprCString): round-trips to original string")

  let emptyRcs = toReprCString("")
  check(emptyRcs.len == 0, "toReprCString(empty): len == 0")
  check($emptyRcs == "", "$(empty ReprCString): returns empty string")

  # toBytes(string)
  let bs = toBytes("abc")
  check(bs.len == 3, "toBytes: correct length")
  check(bs[0] == 0x61'u8, "toBytes: correct first byte")

  let emptyBs = toBytes("")
  check(emptyBs.len == 0, "toBytes(empty): empty seq")

# ---------------------------------------------------------------------------
# Section 2: create_context / installation_name / destroy_context
# ---------------------------------------------------------------------------

proc testContextLifecycle() =
  echo "\n--- testContextLifecycle ---"

  let ctx = create_context(toSlice("lifecycle-test"))
  check(ctx != nil, "create_context: returns non-nil handle")

  let iname = installation_name(ctx)
  defer: destroy_string(iname)
  let inameStr = $iname
  check(inameStr.len > 0, "installation_name: returns non-empty name")
  echo "  installation name: ", inameStr

  destroy_context(ctx)
  echo "  destroy_context: no crash"

# ---------------------------------------------------------------------------
# Section 3: Full two-party conversation flow
# ---------------------------------------------------------------------------
# Exercises: create_intro_bundle, create_new_private_convo, handle_payload,
# send_content, and all four destroy_* procs.
# VecPayload helpers ([], len, items) are also exercised here.

proc testFullConversationFlow() =
  echo "\n--- testFullConversationFlow ---"

  let aliceCtx = create_context(toSlice("alice"))
  check(aliceCtx != nil, "Alice: create_context non-nil")

  let bobCtx = create_context(toSlice("bob"))
  check(bobCtx != nil, "Bob: create_context non-nil")

  # --- create_intro_bundle ---
  var bobIntroRes = create_intro_bundle(bobCtx)
  check(bobIntroRes.error_code == ErrNone,
        "create_intro_bundle: error_code == ErrNone")
  check(bobIntroRes.intro_bytes.len > 0,
        "create_intro_bundle: intro_bytes non-empty")

  # toSeq(VecUint8)
  let introBytes = toSeq(bobIntroRes.intro_bytes)
  check(introBytes.len > 0, "toSeq(VecUint8): produces non-empty seq")

  # destroy_intro_result
  destroy_intro_result(bobIntroRes)
  echo "  destroy_intro_result: no crash"

  # --- create_new_private_convo ---
  var convoRes = create_new_private_convo(
    aliceCtx,
    toSlice(introBytes),
    toSlice("Hello, Bob!")
  )
  check(convoRes.error_code == ErrNone,
        "create_new_private_convo: error_code == ErrNone")

  let aliceConvoId = $convoRes.convo_id
  check(aliceConvoId.len > 0, "create_new_private_convo: convo_id non-empty")
  echo "  Alice-Bob convo_id: ", aliceConvoId

  # len(VecPayload)
  let numPayloads = len(convoRes.payloads)
  check(numPayloads > 0, "len(VecPayload): > 0 payloads in new convo")

  # [](VecPayload, int): subscript access
  let firstPayload = convoRes.payloads[0]
  check(firstPayload.data.len > 0, "VecPayload[0].data: non-empty")
  check(firstPayload.address.len > 0, "VecPayload[0].address: non-empty")
  echo "  first payload address: ", $firstPayload.address

  # items(VecPayload): collect bytes before destroy
  var payloadDatas: seq[seq[byte]] = @[]
  var iterCount = 0
  for p in convoRes.payloads:
    payloadDatas.add(toSeq(p.data))
    inc iterCount
  check(iterCount == numPayloads,
        "items(VecPayload): iterator yields all payloads")

  # destroy_convo_result
  destroy_convo_result(convoRes)
  echo "  destroy_convo_result: no crash"

  # --- handle_payload ---
  var bobSawContent = false
  var bobConvoId = ""
  for pData in payloadDatas:
    var hp = handle_payload(bobCtx, toSlice(pData))
    check(hp.error_code == ErrNone, "handle_payload: error_code == ErrNone")

    let content = toSeq(hp.content)
    if content.len > 0:
      bobConvoId = $hp.convo_id
      check(bobConvoId.len > 0,
            "handle_payload: convo_id non-empty when content present")
      if not bobSawContent:
        check(hp.is_new_convo,
              "handle_payload: is_new_convo == true on first contact")
      bobSawContent = true
      echo "  Bob received content in convo: ", bobConvoId

    destroy_handle_payload_result(hp)

  check(bobSawContent, "handle_payload: Bob received Alice's opening message")
  echo "  destroy_handle_payload_result: no crash"

  # --- send_content ---
  var sendRes = send_content(
    aliceCtx,
    toSlice(aliceConvoId),
    toSlice("How are you, Bob?")
  )
  check(sendRes.error_code == ErrNone,
        "send_content: error_code == ErrNone for valid convo_id")
  check(len(sendRes.payloads) > 0,
        "send_content: returns at least one payload")

  var sendPayloadDatas: seq[seq[byte]] = @[]
  for p in sendRes.payloads:
    sendPayloadDatas.add(toSeq(p.data))

  # destroy_send_content_result
  destroy_send_content_result(sendRes)
  echo "  destroy_send_content_result: no crash"

  # Bob handles follow-up payloads
  for pData in sendPayloadDatas:
    var hp2 = handle_payload(bobCtx, toSlice(pData))
    check(hp2.error_code == ErrNone,
          "handle_payload: Bob handles send_content payload without error")
    destroy_handle_payload_result(hp2)

  destroy_context(aliceCtx)
  destroy_context(bobCtx)
  echo "  both contexts destroyed: no crash"

# ---------------------------------------------------------------------------
# Section 4: Error-case coverage
# ---------------------------------------------------------------------------
# Exercises destroy_* on error results (empty/null Vecs) to confirm they
# do not crash.

proc testErrorCases() =
  echo "\n--- testErrorCases ---"

  let ctx = create_context(toSlice("error-tester"))
  check(ctx != nil, "error-tester: create_context non-nil")

  # send_content with a nonexistent convo_id must fail
  var badSend = send_content(
    ctx,
    toSlice("00000000-0000-0000-0000-nonexistent"),
    toSlice("payload")
  )
  check(badSend.error_code != ErrNone,
        "send_content(bad convo_id): error_code != ErrNone")
  echo "  send_content(bad convo_id) error_code: ", badSend.error_code
  # Destroy error result to confirm destroy handles empty VecPayload
  destroy_send_content_result(badSend)
  echo "  destroy_send_content_result(error result): no crash"

  # create_new_private_convo with garbage bytes must fail with ErrBadIntro
  let badIntro: seq[byte] = @[0xDE'u8, 0xAD'u8, 0xBE'u8, 0xEF'u8]
  var badConvo = create_new_private_convo(
    ctx,
    toSlice(badIntro),
    toSlice("content")
  )
  check(badConvo.error_code == ErrBadIntro,
        "create_new_private_convo(bad intro): error_code == ErrBadIntro")
  destroy_convo_result(badConvo)
  echo "  destroy_convo_result(error result): no crash"

  destroy_context(ctx)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

when isMainModule:
  echo "=== test_all_endpoints: begin ==="

  testHelperProcs()
  testContextLifecycle()
  testFullConversationFlow()
  testErrorCases()

  echo "\n=== ALL TESTS PASSED ==="
