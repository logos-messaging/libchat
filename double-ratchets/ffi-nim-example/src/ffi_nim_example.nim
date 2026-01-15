when defined(macosx):
  {.passL: "-Wl,-rpath,@executable_path/../../target/release".}
when defined(linux):
  {.passL: "-Wl,-rpath,'$ORIGIN/../../target/release'".}

# Portable dynlib name with override capability (-d:RLN_LIB:"...")
when defined(macosx):
  const DR_LIB* {.strdefine.} = "libdouble_ratchets.dylib"
elif defined(linux):
  const DR_LIB* {.strdefine.} = "libdouble_ratchets.so"
elif defined(windows):
  const DR_LIB* {.strdefine.} = "double_ratchets.dll"
else:
  const DR_LIB* {.strdefine.} = "double_ratchets"

type FFIRatchetState* = object

type FFIEncryptResult* = object

type FFIInstallationKeyPair* = object

type CSize* = csize_t

type Vec_uint8* = object
  dataPtr*: ptr uint8
  len*: CSize
  cap*: CSize

type Array_uint8_32* {.bycopy.} = object
  idx*: array[32, uint8]

type CResult_Vec_uint8_Vec_uint8* {.bycopy.} = object ##  <No documentation available>
  ok*: Vec_uint8
  err*: Vec_uint8

proc double_ratchet_init_receiver*(
  shared_secret: Array_uint8_32, keypair: ptr FFIInstallationKeyPair
): ptr FFIRatchetState {.importc, dynlib: DR_LIB.}

proc double_ratchet_init_sender*(
  shared_secret: Array_uint8_32, remote_pub: Array_uint8_32
): ptr FFIRatchetState {.importc, dynlib: DR_LIB.}

proc double_ratchet_encrypt_message*(
  state: ptr FFIRatchetState, plaintext: ptr Vec_uint8
): ptr FFIEncryptResult {.importc, dynlib: DR_LIB.}

proc double_ratchet_descrypt_message*(
  state: ptr FFIRatchetState, encrypted: ptr FFIEncryptResult
): CResult_Vec_uint8_Vec_uint8 {.importc, dynlib: DR_LIB.}

proc ratchet_state_destroy*(state: ptr FFIRatchetState) {.importc, dynlib: DR_LIB.}

proc installation_key_pair_generate*(): ptr FFIInstallationKeyPair {.
  importc, dynlib: DR_LIB
.}

proc installation_key_pair_public*(
  keypair: ptr FFIInstallationKeyPair
): Array_uint8_32 {.importc, dynlib: DR_LIB.}

proc installation_key_pair_destroy*(
  keypair: ptr FFIInstallationKeyPair
) {.importc, dynlib: DR_LIB.}

proc ffi_c_string_free*(s: Vec_uint8) {.importc, cdecl, dynlib: DR_LIB.}

proc asString*(v: Vec_uint8): string =
  if v.dataPtr.isNil or v.len == 0:
    return ""
  result = newString(v.len.int)
  copyMem(addr result[0], v.dataPtr, v.len.int)

when isMainModule:
  echo("start run")

  # === Shared secret (like X3DH) ===
  var sharedSecret: Array_uint8_32
  for i in 0 .. 31:
    sharedSecret.idx[i] = 42'u8

  # === Bob generates DH keypair ===
  let bobKey = installation_key_pair_generate()
  let bobPub = installation_key_pair_public(bobKey)
  echo("bob public key:", bobPub)

  # === Alice initializes as sender ===
  let alice = double_ratchet_init_sender(sharedSecret, bobPub)

  # # === Bob initializes as receiver ===
  let bob = double_ratchet_init_receiver(sharedSecret, bobKey)

  # # === Alice sends message to Bob ===

  var msg1: array[3, uint8] = [11'u8, 12, 13]
  var msg1Vec = Vec_uint8(
    dataPtr: cast[ptr uint8](addr msg1[0]), len: CSize(msg1.len), cap: CSize(msg1.len)
  )

  let enc1 = double_ratchet_encrypt_message(alice, addr msg1Vec)
  let dec1 = double_ratchet_descrypt_message(bob, enc1)

  if dec1.err.dataPtr != nil:
    echo "Bob failed to decrypt: ", asString(dec1.err)
    ffi_c_string_free(dec1.err)
    quit 1
  let res1 = dec1.ok
  var plaintext1: array[3, uint8]
  copyMem(addr plaintext1[0], res1.dataPtr, res1.len.int)
  echo "Bob received: ", plaintext1

  # # === Bob replies (triggers DH ratchet) ===
  var msg2: array[3, uint8] = [1'u8, 2, 3]
  var msg2Vec = Vec_uint8(
    dataPtr: cast[ptr uint8](addr msg2[0]), len: CSize(msg1.len), cap: CSize(msg1.len)
  )
  let enc2 = double_ratchet_encrypt_message(bob, addr msg2Vec)
  let dec2 = double_ratchet_descrypt_message(alice, enc2)

  if dec2.err.dataPtr != nil:
    echo "Alice failed to decrypt: ", asString(dec2.err)
    ffi_c_string_free(dec2.err)
    quit 1
  let res2 = dec2.ok
  var plaintext2: array[3, uint8]
  copyMem(addr plaintext2[0], res2.dataPtr, res2.len.int)
  echo "Alice received: ", plaintext2

  # # === Cleanup ===
  ratchet_state_destroy(alice)
  ratchet_state_destroy(bob)
  installation_key_pair_destroy(bobKey)

  echo("==end==\n")
