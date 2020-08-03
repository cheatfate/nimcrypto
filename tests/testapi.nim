import unittest, strutils
import nimcrypto/[hash, keccak, sha2, ripemd, blake2]

when defined(nimHasUsed): {.used.}

suite "Test API":
  proc hashProc(T: typedesc, input: string, output: var openArray[byte]) =
    var ctx: T
    ctx.init()
    ctx.update(cast[ptr byte](input[0].unsafeAddr), uint(input.len))
    discard ctx.finish(output)
    ctx.clear()

  test "Finish API":
    var y: array[32, byte]
    hashProc(keccak256, "hello", y)
    hashProc(sha256, "hello", y)
    hashProc(ripemd256, "hello", y)
    hashProc(blake2_256, "hello", y)

  test "Digests from strings":
    var h = keccak256.digest("")

    check:
      h == "C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470".toDigest
      h == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".toDigest
      h == MDigest[256].fromHex("C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470")

    when defined(debug):
      const N1 = compiles("".toDigest)
      const N2 = compiles("a".toDigest)
      check:
        N1 == false
        N2 == false

    when Nimcrypto0xPrefix:
      check $("238V".toDigest()) == "0x2380"
    else:
      check $("238V".toDigest()) == "2380"

  test "Digests comparison":
    var h1: MDigest[256]
    var h2: MDigest[512]
    var h3: MDigest[256]
    var h4 = keccak256.digest("")
    var h5: MDigest[2048]
    var h6: MDigest[2048]

    for i in 0..<len(h5.data):
      h5.data[i] = byte(i and 0xFF)
      h6.data[i] = byte(i and 0xFF)

    check:
      h1 != h2
      h1 == h3
      h1 != h4
      h5 == h6

    h5.data[0] = 0x01'u8
    check:
      h5 != h6

  test "Compile time options test":
    when defined(nimcryptoLowercase) and defined(nimcrypto0xPrefix):
      const vector = """
        0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
      """
    elif defined(nimcryptoLowercase):
      const vector = """
        c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
      """
    elif defined(nimcrypto0xPrefix):
      const vector = """
        0xC5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470
      """
    else:
      const vector = """
        C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470
      """
    var h = keccak256.digest("")
    check $h == strip(vector)
