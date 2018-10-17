import unittest
import nimcrypto/[hash, keccak, sha2, ripemd, blake2]

suite "Test API":

  proc hashProc(T: typedesc, input: string, output: var openArray[byte]) =
    var ctx: T
    ctx.init()
    ctx.update(cast[ptr byte](input[0].unsafeAddr), uint(input.len))
    ctx.finish(output)
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
  
    template rejectDigest(x) =
      assert(not compiles(x.toDigest))
      
      expect AssertionError:
        var h = MDigest[256].fromHex(x)

    rejectDigest ""
    rejectDigest "a"
    rejectDigest "238V"
    rejectDigest "A#"
    rejectDigest "C5D2460186F7233C927E7DB2DCC703CKE500B653CA82273B7BFAD8045D85A470" # There is a hidden 'K' symbol in there

  test "Digests comparison":
    var h1: MDigest[256]
    var h2: MDigest[512]
    var h3: MDigest[256]
    var h4 = keccak256.digest("")
    check:
      h1 != h2
      h1 == h3
      h1 != h4
