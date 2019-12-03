import nimcrypto/hash, nimcrypto/sha2, nimcrypto/utils
import unittest

when defined(nimHasUsed): {.used.}

suite "SHA2 Tests":
  const
    code224 = [
      "",
      "abc",
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    ]
    code256 = [
      "",
      "abc",
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    ]
    code384 = [
      "",
      "abc",
      """abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn
         hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"""
    ]
    code512 = [
      "",
      "abc",
      """abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn
         hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"""
    ]
    code512_224 = [
      "abc",
      """abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn
         hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"""
    ]
    code512_256 = [
      "abc",
      """abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn
         hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"""
    ]
    digest224 = [
      "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F",
      "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7",
      "75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525",
    ]
    digest256 = [
      "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
      "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
      "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"
    ]
    digest384 = [
      """38B060A751AC96384CD9327EB1B1E36A21FDB71114BE0743
         4C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B""",
      """CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED163
         1A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7""",
      """09330C33F71147E83D192FC782CD1B4753111B173B3B05D2
         2FA08086E3B0F712FCC7C71A557E2DB966C3E9FA91746039"""
    ]
    digest512 = [
      """CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE
         47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E""",
      """DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A
         2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F""",
      """8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018
         501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909"""
    ]
    digest512_224 = [
      "4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA",
      "23FEC5BB94D60B23308192640B0C453335D664734FE40E7268674AF9"
    ]
    digest512_256 = [
      "53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23",
      "3928E184FB8690F840DA3988121D31BE65CB9D3EF83EE6146FEAC861E19B563A"
    ]

    digest1ma224 = "20794655980C91D8BBB4C1EA97618A4BF03F42581948B2EE4EE7AD67"
    digest1ma256 = """
      CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0"""
    digest1ma384 = """
      9D0E1809716474CB086E834E310A4A1CED149E9C00F248527972CEC5704C2A5B
      07B8B3DC38ECC4EBAE97DDD87F3D8985"""
    digest1ma512 = """
      E718483D0CE769644E2E42C7BC15B4638E1F98B13B2044285632A803AFA973EB
      DE0FF244877EA60A4CB0432CE577C31BEB009C5C2C49AA2E4EADB217AD8CC09B"""

  var ctx224: sha224
  var ctx256: sha256
  var ctx384: sha384
  var ctx512: sha512
  var ctx512224: sha512_224
  var ctx512256: sha512_256
  var i = 0

  test "SHA2 224/256/384/512/512_224/512-256 block sizes":
    check:
      sha224.sizeBlock == 64
      sha256.sizeBlock == 64
      sha384.sizeBlock == 128
      sha512.sizeBlock == 128
      sha512_224.sizeBlock == 128
      sha512_256.sizeBlock == 128
      ctx224.sizeBlock == 64
      ctx256.sizeBlock == 64
      ctx384.sizeBlock == 128
      ctx512.sizeBlock == 128
      ctx512224.sizeBlock == 128
      ctx512256.sizeBlock == 128

  test "SHA2 224/256/384/512/224_512/256_512 digest sizes":
    check:
      sha224.sizeDigest == 28
      sha256.sizeDigest == 32
      sha384.sizeDigest == 48
      sha512.sizeDigest == 64
      sha512_224.sizeDigest == 28
      sha512_256.sizeDigest == 32
      ctx224.sizeDigest == 28
      ctx256.sizeDigest == 32
      ctx384.sizeDigest == 48
      ctx512.sizeDigest == 64
      ctx512224.sizeDigest == 28
      ctx512256.sizeDigest == 32

  test "SHA2-224 compile-time test vectors":
    const
      check2240 = sha224.digest(code224[0])
      check2241 = sha224.digest(code224[1])
      check2242 = sha224.digest(code224[2])
    check:
      $check2240 == stripSpaces(digest224[0])
      $check2241 == stripSpaces(digest224[1])
      $check2242 == stripSpaces(digest224[2])

  test "SHA2-224 test vectors":
    i = 0
    while i < len(code224):
      var plaintext = stripSpaces(code224[i])
      var digest = stripSpaces(digest224[i])
      ctx224.init()
      if len(plaintext) > 0:
        ctx224.update(cast[ptr uint8](addr plaintext[0]), uint(len(plaintext)))
      else:
        ctx224.update(nil, 0)
      var check1 = $ctx224.finish()
      var check2: string
      if len(plaintext) > 0:
        check2 = $sha224.digest(cast[ptr uint8](addr plaintext[0]),
                                uint(len(plaintext)))
      else:
        check2 = $sha224.digest(nil, 0)
      var check3 = $sha224.digest(plaintext)
      ctx224.init()
      ctx224.update(plaintext)
      var check4 = $ctx224.finish()
      ctx224.clear()
      check:
        check1 == digest
        check2 == digest
        check3 == digest
        check4 == digest
        ctx224.isFullZero() == true
      inc(i)

  test "SHA2-224 empty update() test":
    var data: seq[byte]
    var ctx1, ctx2: sha224
    var msg = cast[seq[byte]](stripSpaces(code224[1]))
    var edigest = fromHex(stripSpaces(digest224[1]))
    ctx1.init()
    ctx2.init()
    ctx1.update(msg)
    ctx2.update(addr msg[0], uint(len(msg)))
    ctx1.update(data)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  test "SHA2-256 compile-time test vectors":
    const
      check2560 = sha256.digest(code256[0])
      check2561 = sha256.digest(code256[1])
      check2562 = sha256.digest(code256[2])
    check:
      $check2560 == stripSpaces(digest256[0])
      $check2561 == stripSpaces(digest256[1])
      $check2562 == stripSpaces(digest256[2])

  test "SHA2-256 test vectors":
    i = 0
    while i < len(code256):
      var plaintext = stripSpaces(code256[i])
      var digest = stripSpaces(digest256[i])
      ctx256.init()
      if len(plaintext) > 0:
        ctx256.update(cast[ptr uint8](addr plaintext[0]), uint(len(plaintext)))
      else:
        ctx256.update(nil, 0)
      var check1 = $ctx256.finish()
      var check2: string
      if len(plaintext) > 0:
        check2 = $sha256.digest(cast[ptr uint8](addr plaintext[0]),
                                uint(len(plaintext)))
      else:
        check2 = $sha256.digest(nil, 0)
      var check3 = $sha256.digest(plaintext)
      ctx256.init()
      ctx256.update(plaintext)
      var check4 = $ctx256.finish()
      ctx256.clear()
      check:
        check1 == digest
        check2 == digest
        check3 == digest
        check4 == digest
        ctx256.isFullZero() == true
      inc(i)

  test "SHA2-256 empty update() test":
    var data: seq[byte]
    var ctx1, ctx2: sha256
    var msg = cast[seq[byte]](stripSpaces(code256[1]))
    var edigest = fromHex(stripSpaces(digest256[1]))
    ctx1.init()
    ctx2.init()
    ctx1.update(msg)
    ctx2.update(addr msg[0], uint(len(msg)))
    ctx1.update(data)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  test "SHA2-384 compile-time test vectors":
    const
      check3840 = sha384.digest(stripSpaces(code384[0]))
      check3841 = sha384.digest(stripSpaces(code384[1]))
      check3842 = sha384.digest(stripSpaces(code384[2]))
    check:
      $check3840 == stripSpaces(digest384[0])
      $check3841 == stripSpaces(digest384[1])
      $check3842 == stripSpaces(digest384[2])

  test "SHA2-384 test vectors":
    i = 0
    while i < len(code384):
      var plaintext = stripSpaces(code384[i])
      var digest = stripSpaces(digest384[i])
      ctx384.init()
      if len(plaintext) > 0:
        ctx384.update(cast[ptr uint8](addr plaintext[0]), uint(len(plaintext)))
      else:
        ctx384.update(nil, 0)
      var check1 = $ctx384.finish()
      var check2: string
      if len(plaintext) > 0:
        check2 = $sha384.digest(cast[ptr uint8](addr plaintext[0]),
                                uint(len(plaintext)))
      else:
        check2 = $sha384.digest(nil, 0)

      var check3 = $sha384.digest(plaintext)
      ctx384.init()
      ctx384.update(plaintext)
      var check4 = $ctx384.finish()
      ctx384.clear()
      check:
        check1 == digest
        check2 == digest
        check3 == digest
        check4 == digest
        ctx384.isFullZero() == true
      inc(i)

  test "SHA2-384 empty update() test":
    var data: seq[byte]
    var ctx1, ctx2: sha384
    var msg = cast[seq[byte]](stripSpaces(code384[1]))
    var edigest = fromHex(stripSpaces(digest384[1]))
    ctx1.init()
    ctx2.init()
    ctx1.update(msg)
    ctx2.update(addr msg[0], uint(len(msg)))
    ctx1.update(data)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  test "SHA2-512 compile-time test vectors":
    const
      check5120 = sha512.digest(stripSpaces(code512[0]))
      check5121 = sha512.digest(stripSpaces(code512[1]))
      check5122 = sha512.digest(stripSpaces(code512[2]))
    check:
      $check5120 == stripSpaces(digest512[0])
      $check5121 == stripSpaces(digest512[1])
      $check5122 == stripSpaces(digest512[2])

  test "SHA2-512 test vectors":
    i = 0
    while i < len(code512):
      var plaintext = stripSpaces(code512[i])
      var digest = stripSpaces(digest512[i])
      ctx512.init()
      if len(plaintext) > 0:
        ctx512.update(cast[ptr uint8](addr plaintext[0]), uint(len(plaintext)))
      else:
        ctx512.update(nil, 0)
      var check1 = $ctx512.finish()
      var check2: string
      if len(plaintext) > 0:
        check2 = $sha512.digest(cast[ptr uint8](addr plaintext[0]),
                                uint(len(plaintext)))
      else:
        check2 = $sha512.digest(nil, 0)
      var check3 = $sha512.digest(plaintext)
      ctx512.init()
      ctx512.update(plaintext)
      var check4 = $ctx512.finish()
      ctx512.clear()
      check:
        check1 == digest
        check2 == digest
        check3 == digest
        check4 == digest
        ctx512.isFullZero() == true
      inc(i)

  test "SHA2-512 empty update() test":
    var data: seq[byte]
    var ctx1, ctx2: sha512
    var msg = cast[seq[byte]](stripSpaces(code512[1]))
    var edigest = fromHex(stripSpaces(digest512[1]))
    ctx1.init()
    ctx2.init()
    ctx1.update(msg)
    ctx2.update(addr msg[0], uint(len(msg)))
    ctx1.update(data)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  test "SHA2-512/224 compile-time test vectors":
    const
      check5122240 = sha512_224.digest(stripSpaces(code512_224[0]))
      check5122241 = sha512_224.digest(stripSpaces(code512_224[1]))
    check:
      $check5122240 == stripSpaces(digest512_224[0])
      $check5122241 == stripSpaces(digest512_224[1])

  test "SHA2-512/224 test vectors":
    i = 0
    while i < len(code512_224):
      var plaintext = stripSpaces(code512_224[i])
      var digest = stripSpaces(digest512_224[i])
      ctx512_224.init()
      ctx512_224.update(cast[ptr uint8](addr plaintext[0]),
                        uint(len(plaintext)))
      var check1 = $ctx512_224.finish()
      var check2 = $sha512_224.digest(cast[ptr uint8](addr plaintext[0]),
                                      uint(len(plaintext)))
      var check3 = $sha512_224.digest(plaintext)
      ctx512_224.init()
      ctx512_224.update(plaintext)
      var check4 = $ctx512_224.finish()
      ctx512_224.clear()
      check:
        check1 == digest
        check2 == digest
        check3 == digest
        check4 == digest
        ctx512_224.isFullZero() == true
      inc(i)

  test "SHA2-512/224 empty update() test":
    var data: seq[byte]
    var ctx1, ctx2: sha512_224
    var msg = cast[seq[byte]](stripSpaces(code512_224[1]))
    var edigest = fromHex(stripSpaces(digest512_224[1]))
    ctx1.init()
    ctx2.init()
    ctx1.update(msg)
    ctx2.update(addr msg[0], uint(len(msg)))
    ctx1.update(data)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  test "SHA2-512/256 compile-time test vectors":
    const
      check5122560 = sha512_256.digest(stripSpaces(code512_256[0]))
      check5122561 = sha512_256.digest(stripSpaces(code512_256[1]))
    check:
      $check5122560 == stripSpaces(digest512_256[0])
      $check5122561 == stripSpaces(digest512_256[1])

  test "SHA2-512/256 test vectors":
    i = 0
    while i < len(code512_256):
      var plaintext = stripSpaces(code512_256[i])
      var digest = stripSpaces(digest512_256[i])
      ctx512_256.init()
      ctx512_256.update(cast[ptr uint8](addr plaintext[0]),
                        uint(len(plaintext)))
      var check1 = $ctx512_256.finish()
      var check2 = $sha512_256.digest(cast[ptr uint8](addr plaintext[0]),
                                      uint(len(plaintext)))
      var check3 = $sha512_256.digest(plaintext)
      ctx512_256.init()
      ctx512_256.update(plaintext)
      var check4 = $ctx512_256.finish()
      ctx512_256.clear()
      check:
        check1 == digest
        check2 == digest
        check3 == digest
        check4 == digest
        ctx512_256.isFullZero() == true
      inc(i)

  test "SHA2-512/256 empty update() test":
    var data: seq[byte]
    var ctx1, ctx2: sha512_256
    var msg = cast[seq[byte]](stripSpaces(code512_256[1]))
    var edigest = fromHex(stripSpaces(digest512_256[1]))
    ctx1.init()
    ctx2.init()
    ctx1.update(msg)
    ctx2.update(addr msg[0], uint(len(msg)))
    ctx1.update(data)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  proc millionAtest(t: typedesc): string =
    var ctx: t
    ctx.init()
    for i in 0 ..< 1_000_000:
      ctx.update("a")
    result = $ctx.finish()

  test "SHA2-224 million(a) test":
    check sha224.millionAtest() == stripSpaces(digest1ma224)

  test "SHA2-256 million(a) test":
    check sha256.millionAtest() == stripSpaces(digest1ma256)

  test "SHA2-384 million(a) test":
    check sha384.millionAtest() == stripSpaces(digest1ma384)

  test "SHA2-512 million(a) test":
    check sha512.millionAtest() == stripSpaces(digest1ma512)
