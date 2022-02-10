import nimcrypto/hash, nimcrypto/keccak, nimcrypto/utils
from strutils import parseInt
import unittest

when defined(nimHasUsed): {.used.}

suite "KECCAK/SHA3 Tests":
  ## KECCAK TESTS
  ## This tests performed only for full byte message value

  const
    codes = [
      "abc",
      "",
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      """abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn
         hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"""
    ]
    sdigest224 = [
      "E642824C3F8CF24AD09234EE7D3C766FC9A3A5168D0C94AD73B46FDF",
      "6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7",
      "8A24108B154ADA21C9FD5574494479BA5C7E7AB76EF264EAD0FCCE33",
      "543E6868E1666C1A643630DF77367AE5A62A85070A51C14CBF665CBC",
      "D69335B93325192E516A912E6D19A15CB51C6ED5C15243E7A7FD653C",
      "C6D66E77AE289566AFB2CE39277752D6DA2A3C46010F1E0A0970FF60"
    ]
    kdigest224 = [
      "C30411768506EBE1C2871B1EE2E87D38DF342317300A9B97A95EC6A8",
      "F71837502BA8E10837BDD8D365ADB85591895602FC552B48B7390ABD",
      "E51FAA2B4655150B931EE8D700DC202F763CA5F962C529EAE55012B6",
      "344298994B1B06873EAE2CE739C425C47291A2E24189E01B524F88DC"
    ]
    sdigest256 = [
      "3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532",
      "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A",
      "41C0DBA2A9D6240849100376A8235E2C82E1B9998A999E21DB32DD97496D3376",
      "916F6061FE879741CA6469B43971DFDB28B1A32DC36CB3254E812BE27AAD1D18",
      "5C8875AE474A3634BA4FD55EC85BFFD661F32ACA75C6D699D0CDCB6C115891C1",
      "ECBBC42CBF296603ACB2C6BC0410EF4378BAFB24B710357F12DF607758B33E2B"
    ]
    kdigest256 = [
      "4E03657AEA45A94FC7D47BA826C8D667C0D1E6E33A64A036EC44F58FA12D6C45",
      "C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470",
      "45D3B367A6904E6E8D502EE04999A7C27647F91FA845D456525FD352AE3D7371",
      "F519747ED599024F3882238E5AB43960132572B7345FBEB9A90769DAFD21AD67"
    ]
    sdigest384 = [
      """EC01498288516FC926459F58E2C6AD8DF9B473CB0FC08C25
         96DA7CF0E49BE4B298D88CEA927AC7F539F1EDF228376D25""",
      """0C63A75B845E4F7D01107D852E4C2485C51A50AAAA94FC61
         995E71BBEE983A2AC3713831264ADB47FB6BD1E058D5F004""",
      """991C665755EB3A4B6BBDFB75C78A492E8C56A22C5C4D7E42
         9BFDBC32B9D4AD5AA04A1F076E62FEA19EEF51ACD0657C22""",
      """79407D3B5916B59C3E30B09822974791C313FB9ECC849E40
         6F23592D04F625DC8C709B98B43B3852B337216179AA7FC7""",
      """EEE9E24D78C1855337983451DF97C8AD9EEDF256C6334F8E
         948D252D5E0E76847AA0774DDB90A842190D2C558B4B8340""",
      """A04296F4FCAAE14871BB5AD33E28DCF69238B04204D9941B
         8782E816D014BCB7540E4AF54F30D578F1A1CA2930847A12"""
    ]
    kdigest384 = [
      """F7DF1165F033337BE098E7D288AD6A2F74409D7A60B49C36
         642218DE161B1F99F8C681E4AFAF31A34DB29FB763E3C28E""",
      """2C23146A63A29ACF99E73B88F8C24EAA7DC60AA771780CCC
         006AFBFA8FE2479B2DD2B21362337441AC12B515911957FF""",
      """B41E8896428F1BCBB51E17ABD6ACC98052A3502E0D5BF7FA
         1AF949B4D3C855E7C4DC2C390326B3F3E74C7B1E2B9A3657""",
      """CC063F34685135368B34F7449108F6D10FA727B09D696EC5
         331771DA46A923B6C34DBD1D4F77E595689C1F3800681C28"""
    ]
    sdigest512 = [
      """B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E
         10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0""",
      """A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A6
         15B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26""",
      """04A371E84ECFB5B8B77CB48610FCA8182DD457CE6F326A0FD3D7EC2F1E91636D
         EE691FBE0C985302BA1B0D8DC78C086346B533B49C030D99A27DAF1139D6E75E""",
      """AFEBB2EF542E6579C50CAD06D2E578F9F8DD6881D7DC824D26360FEEBF18A4FA
         73E3261122948EFCFD492E74E82E2189ED0FB440D187F382270CB455F21DD185""",
      """3C3A876DA14034AB60627C077BB98F7E120A2A5370212DFFB3385A18D4F38859
         ED311D0A9D5141CE9CC5C66EE689B266A8AA18ACE8282A0E0DB596C90B0A7B87""",
      """235FFD53504EF836A1342B488F483B396EABBFE642CF78EE0D31FEEC788B23D0
         D18D5C339550DD5958A500D4B95363DA1B5FA18AFFC1BAB2292DC63B7D85097C"""
    ]
    kdigest512 = [
      """18587DC2EA106B9A1563E32B3312421CA164C7F1F07BC922A9C83D77CEA3A1E5
         D0C69910739025372DC14AC9642629379540C17E2A65B19D77AA511A9D00BB96""",
      """0EAB42DE4C3CEB9235FC91ACFFE746B29C29A8C366B7C60E4E67C466F36A4304
         C00FA9CAF9D87976BA469BCBE06713B435F091EF2769FB160CDAB33D3670680E""",
      """6AA6D3669597DF6D5A007B00D09C20795B5C4218234E1698A944757A488ECDC0
         9965435D97CA32C3CFED7201FF30E070CD947F1FC12B9D9214C467D342BCBA5D""",
      """AC2FB35251825D3AA48468A9948C0A91B8256F6D97D8FA4160FAFF2DD9DFCC24
         F3F1DB7A983DAD13D53439CCAC0B37E24037E7B95F80F59F37A2F683C4BA4682"""
    ]

  type
    TestVector = object
      length: int
      message: string
      digest: string

  iterator testVectors(filename: string): TestVector =
    var state = 0
    var vector = TestVector()
    var file = open(filename)
    while not endOfFile(file):
      var line = file.readLine()
      if len(line) > 0:
        if line[0..5] == "Len = ":
          let lstr = line[6..(len(line) - 1)]
          vector.length = parseInt(lstr)
          inc(state)
        elif line[0..5] == "Msg = ":
          let mstr = line[6..(len(line) - 1)]
          vector.message = mstr
          inc(state)
        elif line[0..4] == "MD = ":
          let dstr = line[5..(len(line) - 1)]
          vector.digest = dstr
          inc(state)
      if state == 3:
        state = 0
        yield vector
        vector = TestVector()
    close(file)

  var kec224: keccak224
  var kec256: keccak256
  var kec384: keccak384
  var kec512: keccak512

  test "SHA3/KECCAK 224/256/384/512 block sizes":
    var k224: keccak224
    var k256: keccak256
    var k384: keccak384
    var k512: keccak512
    var s224: sha3_224
    var s256: sha3_256
    var s384: sha3_384
    var s512: sha3_512
    check:
      k224.sizeBlock == 200
      k256.sizeBlock == 200
      k384.sizeBlock == 200
      k512.sizeBlock == 200
      s224.sizeBlock == 200
      s256.sizeBlock == 200
      s384.sizeBlock == 200
      s512.sizeBlock == 200
      keccak224.sizeBlock == 200
      keccak256.sizeBlock == 200
      keccak384.sizeBlock == 200
      keccak512.sizeBlock == 200
      sha3_224.sizeBlock == 200
      sha3_256.sizeBlock == 200
      sha3_384.sizeBlock == 200
      sha3_512.sizeBlock == 200

  test "SHA3/KECCAK 224/256/384/512 digest sizes":
    var k224: keccak224
    var k256: keccak256
    var k384: keccak384
    var k512: keccak512
    var s224: sha3_224
    var s256: sha3_256
    var s384: sha3_384
    var s512: sha3_512
    check:
      k224.sizeDigest == 28
      k256.sizeDigest == 32
      k384.sizeDigest == 48
      k512.sizeDigest == 64
      s224.sizeDigest == 28
      s256.sizeDigest == 32
      s384.sizeDigest == 48
      s512.sizeDigest == 64
      keccak224.sizeDigest == 28
      keccak256.sizeDigest == 32
      keccak384.sizeDigest == 48
      keccak512.sizeDigest == 64
      sha3_224.sizeDigest == 28
      sha3_256.sizeDigest == 32
      sha3_384.sizeDigest == 48
      sha3_512.sizeDigest == 64

  test "SHAKE-128/256 block sizes":
    var s128: shake128
    var s256: shake256
    check:
      s128.sizeBlock == 200
      s256.sizeBlock == 200
      shake128.sizeBlock == 200
      shake256.sizeBlock == 200

  test "SHAKE-128/256 digest sizes":
    var s128: shake128
    var s256: shake256
    check:
      s128.sizeDigest == 16
      s256.sizeDigest == 32
      shake128.sizeDigest == 16
      shake256.sizeDigest == 32

  test "KECCAK-224/256/384/512 compile-time test vectors":
    const
      check2240 = keccak224.digest(stripSpaces(codes[0]))
      check2241 = keccak224.digest(stripSpaces(codes[1]))
      check2242 = keccak224.digest(stripSpaces(codes[2]))
      check2243 = keccak224.digest(stripSpaces(codes[3]))

      check2560 = keccak256.digest(stripSpaces(codes[0]))
      check2561 = keccak256.digest(stripSpaces(codes[1]))
      check2562 = keccak256.digest(stripSpaces(codes[2]))
      check2563 = keccak256.digest(stripSpaces(codes[3]))

      check3840 = keccak384.digest(stripSpaces(codes[0]))
      check3841 = keccak384.digest(stripSpaces(codes[1]))
      check3842 = keccak384.digest(stripSpaces(codes[2]))
      check3843 = keccak384.digest(stripSpaces(codes[3]))

      check5120 = keccak512.digest(stripSpaces(codes[0]))
      check5121 = keccak512.digest(stripSpaces(codes[1]))
      check5122 = keccak512.digest(stripSpaces(codes[2]))
      check5123 = keccak512.digest(stripSpaces(codes[3]))
    check:
      $check2240 == stripSpaces(kdigest224[0])
      $check2241 == stripSpaces(kdigest224[1])
      $check2242 == stripSpaces(kdigest224[2])
      $check2243 == stripSpaces(kdigest224[3])

      $check2560 == stripSpaces(kdigest256[0])
      $check2561 == stripSpaces(kdigest256[1])
      $check2562 == stripSpaces(kdigest256[2])
      $check2563 == stripSpaces(kdigest256[3])

      $check3840 == stripSpaces(kdigest384[0])
      $check3841 == stripSpaces(kdigest384[1])
      $check3842 == stripSpaces(kdigest384[2])
      $check3843 == stripSpaces(kdigest384[3])

      $check5120 == stripSpaces(kdigest512[0])
      $check5121 == stripSpaces(kdigest512[1])
      $check5122 == stripSpaces(kdigest512[2])
      $check5123 == stripSpaces(kdigest512[3])

  test "KECCAK-224 test vectors":
    ## KECCAK-224
    for item in testVectors("tests/ShortMsgKAT_224.txt"):
      kec224.init()
      if (item.length mod 8) == 0:
        var data: seq[uint8]
        var length = item.length div 8
        data = newSeq[uint8](length)
        var msg = fromHex(item.message)
        # Nim do not allow `addr data[0]` if `data` is empty array,
        # so we need to handle it in different way
        if len(data) > 0:
          copyMem(cast[pointer](addr data[0]), cast[pointer](addr msg[0]),
                  len(msg))
          kec224.update(addr data[0], uint(length))
          var check1 = $kec224.finish()
          var check2 = $keccak224.digest(addr data[0], uint(length))
          kec224.clear()
          check:
            item.digest == check1
            item.digest == check2
            kec224.isFullZero() == true
        else:
          kec224.update(nil, uint(length))
          var check1 = $kec224.finish()
          var check2 = $keccak224.digest(nil, uint(length))
          kec224.clear()
          check:
            item.digest == check1
            item.digest == check2
            kec224.isFullZero() == true

        var check3 = $keccak224.digest(data)
        check item.digest == check3

  test "KECCAK-224 empty update() test":
    var data: seq[byte]
    var ctx1, ctx2: keccak224
    var msg = cast[seq[byte]](stripSpaces(codes[0]))
    var edigest = fromHex(stripSpaces(kdigest224[0]))
    ctx1.init()
    ctx2.init()
    ctx1.update(msg)
    ctx2.update(addr msg[0], uint(len(msg)))
    ctx1.update(data)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  test "KECCAK-256 test vectors":
    ## KECCAK-256
    for item in testVectors("tests/ShortMsgKAT_256.txt"):
      kec256.init()
      if (item.length mod 8) == 0:
        var data: seq[uint8]
        var length = item.length div 8
        data = newSeq[uint8](length)
        var msg = fromHex(item.message)
        # Nim do not allow `addr data[0]` if `data` is empty array,
        # so we need to handle it in different way
        if len(data) > 0:
          copyMem(cast[pointer](addr data[0]), cast[pointer](addr msg[0]),
                  len(msg))
          kec256.update(addr data[0], uint(length))
          var check1 = $kec256.finish()
          var check2 = $keccak256.digest(addr data[0], uint(length))
          kec256.clear()
          check:
            item.digest == check1
            item.digest == check2
            kec256.isFullZero() == true
        else:
          kec256.update(nil, uint(length))
          var check1 = $kec256.finish()
          var check2 = $keccak256.digest(nil, uint(length))
          kec256.clear()
          check:
            item.digest == check1
            item.digest == check2
            kec256.isFullZero() == true
        var check3 = $keccak256.digest(data)
        check item.digest == check3

  test "KECCAK-256 empty update() test":
    var data: seq[byte]
    var ctx1, ctx2: keccak256
    var msg = cast[seq[byte]](stripSpaces(codes[0]))
    var edigest = fromHex(stripSpaces(kdigest256[0]))
    ctx1.init()
    ctx2.init()
    ctx1.update(msg)
    ctx2.update(addr msg[0], uint(len(msg)))
    ctx1.update(data)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  test "KECCAK-384 test vectors":
    ## KECCAK-384
    for item in testVectors("tests/ShortMsgKAT_384.txt"):
      kec384.init()
      if (item.length mod 8) == 0:
        var data: seq[uint8]
        var length = item.length div 8
        data = newSeq[uint8](length)
        var msg = fromHex(item.message)
        # Nim do not allow `addr data[0]` if `data` is empty array,
        # so we need to handle it in different way
        if len(data) > 0:
          copyMem(cast[pointer](addr data[0]), cast[pointer](addr msg[0]),
                  len(msg))
          kec384.update(addr data[0], uint(length))
          var check1 = $kec384.finish()
          var check2 = $keccak384.digest(addr data[0], uint(length))
          kec384.clear()
          check:
            item.digest == check1
            item.digest == check2
            kec384.isFullZero() == true
        else:
          kec384.update(nil, uint(length))
          var check1 = $kec384.finish()
          var check2 = $keccak384.digest(nil, uint(length))
          kec384.clear()
          check:
            item.digest == check1
            item.digest == check2
            kec384.isFullZero() == true
        var check3 = $keccak384.digest(data)
        check item.digest == check3

  test "KECCAK-384 empty update() test":
    var data: seq[byte]
    var ctx1, ctx2: keccak384
    var msg = cast[seq[byte]](stripSpaces(codes[0]))
    var edigest = fromHex(stripSpaces(kdigest384[0]))
    ctx1.init()
    ctx2.init()
    ctx1.update(msg)
    ctx2.update(addr msg[0], uint(len(msg)))
    ctx1.update(data)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  test "KECCAK-512 test vectors":
    ## KECCAK-512
    for item in testVectors("tests/ShortMsgKAT_512.txt"):
      kec512.init()
      if (item.length mod 8) == 0:
        var data: seq[uint8]
        var length = item.length div 8
        data = newSeq[uint8](length)
        var msg = fromHex(item.message)
        # Nim do not allow `addr data[0]` if `data` is empty array,
        # so we need to handle it in different way
        if len(data) > 0:
          copyMem(cast[pointer](addr data[0]), cast[pointer](addr msg[0]),
                  len(msg))
          kec512.update(addr data[0], uint(length))
          var check1 = $kec512.finish()
          var check2 = $keccak512.digest(addr data[0], uint(length))
          kec512.clear()
          check:
            item.digest == check1
            item.digest == check2
            kec512.isFullZero() == true
        else:
          kec512.update(nil, uint(length))
          var check1 = $kec512.finish()
          var check2 = $keccak512.digest(nil, uint(length))
          kec512.clear()
          check:
            item.digest == check1
            item.digest == check2
            kec512.isFullZero() == true
        var check3 = $keccak512.digest(data)
        check item.digest == check3

  test "KECCAK-512 empty update() test":
    var data: seq[byte]
    var ctx1, ctx2: keccak512
    var msg = cast[seq[byte]](stripSpaces(codes[0]))
    var edigest = fromHex(stripSpaces(kdigest512[0]))
    ctx1.init()
    ctx2.init()
    ctx1.update(msg)
    ctx2.update(addr msg[0], uint(len(msg)))
    ctx1.update(data)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  ## SHA3 TESTS

  # proc extremeTest[T: sha3 | keccak](ctx: T): string =
  #   var msg = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
  #   ctx.init()
  #   for i in 1..16_777_216:
  #     ctx.update(cast[ptr uint8](addr msg[0]), uint(len(msg)))
  #   result = $ctx.finish()

  test "SHA3 224/256/384/512 compile-time test vectors":
    const
      check2240 = sha3_224.digest(stripSpaces(codes[0]))
      check2241 = sha3_224.digest(stripSpaces(codes[1]))
      check2242 = sha3_224.digest(stripSpaces(codes[2]))
      check2243 = sha3_224.digest(stripSpaces(codes[3]))

      check2560 = sha3_256.digest(stripSpaces(codes[0]))
      check2561 = sha3_256.digest(stripSpaces(codes[1]))
      check2562 = sha3_256.digest(stripSpaces(codes[2]))
      check2563 = sha3_256.digest(stripSpaces(codes[3]))

      check3840 = sha3_384.digest(stripSpaces(codes[0]))
      check3841 = sha3_384.digest(stripSpaces(codes[1]))
      check3842 = sha3_384.digest(stripSpaces(codes[2]))
      check3843 = sha3_384.digest(stripSpaces(codes[3]))

      check5120 = sha3_512.digest(stripSpaces(codes[0]))
      check5121 = sha3_512.digest(stripSpaces(codes[1]))
      check5122 = sha3_512.digest(stripSpaces(codes[2]))
      check5123 = sha3_512.digest(stripSpaces(codes[3]))
    check:
      $check2240 == stripSpaces(sdigest224[0])
      $check2241 == stripSpaces(sdigest224[1])
      $check2242 == stripSpaces(sdigest224[2])
      $check2243 == stripSpaces(sdigest224[3])

      $check2560 == stripSpaces(sdigest256[0])
      $check2561 == stripSpaces(sdigest256[1])
      $check2562 == stripSpaces(sdigest256[2])
      $check2563 == stripSpaces(sdigest256[3])

      $check3840 == stripSpaces(sdigest384[0])
      $check3841 == stripSpaces(sdigest384[1])
      $check3842 == stripSpaces(sdigest384[2])
      $check3843 == stripSpaces(sdigest384[3])

      $check5120 == stripSpaces(sdigest512[0])
      $check5121 == stripSpaces(sdigest512[1])
      $check5122 == stripSpaces(sdigest512[2])
      $check5123 == stripSpaces(sdigest512[3])

  var sha224, osha224: sha3_224
  var sha256, osha256: sha3_256
  var sha384, osha384: sha3_384
  var sha512, osha512: sha3_512

  test "SHA3 224/256/384/512 test vectors":
    for i in 0..(len(codes) - 1):
      var msg = stripSpaces(codes[i])
      sha224.init()
      sha256.init()
      sha384.init()
      sha512.init()
      osha224.init()
      osha256.init()
      osha384.init()
      osha512.init()
      if len(msg) == 0:
        sha224.update(nil, 0'u)
        sha256.update(nil, 0'u)
        sha384.update(nil, 0'u)
        sha512.update(nil, 0'u)
      else:
        sha224.update(cast[ptr uint8](addr msg[0]), uint(len(msg)))
        sha256.update(cast[ptr uint8](addr msg[0]), uint(len(msg)))
        sha384.update(cast[ptr uint8](addr msg[0]), uint(len(msg)))
        sha512.update(cast[ptr uint8](addr msg[0]), uint(len(msg)))
      osha224.update(msg)
      osha256.update(msg)
      osha384.update(msg)
      osha512.update(msg)
      check:
        $sha224.finish() == stripSpaces(sdigest224[i])
        $sha256.finish() == stripSpaces(sdigest256[i])
        $sha384.finish() == stripSpaces(sdigest384[i])
        $sha512.finish() == stripSpaces(sdigest512[i])
        $osha224.finish() == stripSpaces(sdigest224[i])
        $osha256.finish() == stripSpaces(sdigest256[i])
        $osha384.finish() == stripSpaces(sdigest384[i])
        $osha512.finish() == stripSpaces(sdigest512[i])
      sha224.clear()
      sha256.clear()
      sha384.clear()
      sha512.clear()
      osha224.clear()
      osha256.clear()
      osha384.clear()
      osha512.clear()
      check:
        sha224.isFullZero() == true
        sha256.isFullZero() == true
        sha384.isFullZero() == true
        sha512.isFullZero() == true
        osha224.isFullZero() == true
        osha256.isFullZero() == true
        osha384.isFullZero() == true
        osha512.isFullZero() == true
      # One liner test
      if len(msg) > 0:
        var dcheck224 = $sha3_224.digest(cast[ptr uint8](addr msg[0]),
                                         uint(len(msg)))
        var dcheck256 = $sha3_256.digest(cast[ptr uint8](addr msg[0]),
                                         uint(len(msg)))
        var dcheck384 = $sha3_384.digest(cast[ptr uint8](addr msg[0]),
                                         uint(len(msg)))
        var dcheck512 = $sha3_512.digest(cast[ptr uint8](addr msg[0]),
                                         uint(len(msg)))
        check:
          dcheck224 == stripSpaces(sdigest224[i])
          dcheck256 == stripSpaces(sdigest256[i])
          dcheck384 == stripSpaces(sdigest384[i])
          dcheck512 == stripSpaces(sdigest512[i])
      else:
        var dcheck224 = $sha3_224.digest(nil, 0'u)
        var dcheck256 = $sha3_256.digest(nil, 0'u)
        var dcheck384 = $sha3_384.digest(nil, 0'u)
        var dcheck512 = $sha3_512.digest(nil, 0'u)
        check:
          dcheck224 == stripSpaces(sdigest224[i])
          dcheck256 == stripSpaces(sdigest256[i])
          dcheck384 == stripSpaces(sdigest384[i])
          dcheck512 == stripSpaces(sdigest512[i])
      # openArray[T] test
      check:
        $sha3_224.digest(msg) == stripSpaces(sdigest224[i])
        $sha3_256.digest(msg) == stripSpaces(sdigest256[i])
        $sha3_384.digest(msg) == stripSpaces(sdigest384[i])
        $sha3_512.digest(msg) == stripSpaces(sdigest512[i])

  test "SHA3-224 empty update() test":
    var data: seq[byte]
    var ctx1, ctx2: sha3_224
    var msg = cast[seq[byte]](stripSpaces(codes[0]))
    var edigest = fromHex(stripSpaces(sdigest224[0]))
    ctx1.init()
    ctx2.init()
    ctx1.update(msg)
    ctx2.update(addr msg[0], uint(len(msg)))
    ctx1.update(data)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  test "SHA3-256 empty update() test":
    var data: seq[byte]
    var ctx1, ctx2: sha3_256
    var msg = cast[seq[byte]](stripSpaces(codes[0]))
    var edigest = fromHex(stripSpaces(sdigest256[0]))
    ctx1.init()
    ctx2.init()
    ctx1.update(msg)
    ctx2.update(addr msg[0], uint(len(msg)))
    ctx1.update(data)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  test "SHA3-384 empty update() test":
    var data: seq[byte]
    var ctx1, ctx2: sha3_384
    var msg = cast[seq[byte]](stripSpaces(codes[0]))
    var edigest = fromHex(stripSpaces(sdigest384[0]))
    ctx1.init()
    ctx2.init()
    ctx1.update(msg)
    ctx2.update(addr msg[0], uint(len(msg)))
    ctx1.update(data)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  test "SHA3-512 empty update() test":
    var data: seq[byte]
    var ctx1, ctx2: sha3_512
    var msg = cast[seq[byte]](stripSpaces(codes[0]))
    var edigest = fromHex(stripSpaces(sdigest512[0]))
    ctx1.init()
    ctx2.init()
    ctx1.update(msg)
    ctx2.update(addr msg[0], uint(len(msg)))
    ctx1.update(data)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  test "SHA3 224/256/384/512 million test":
    # Million 'a' test
    sha224.init()
    sha256.init()
    sha384.init()
    sha512.init()
    osha224.init()
    osha256.init()
    osha384.init()
    osha512.init()
    var msg = "a"
    for i in 1..1_000_000:
      sha224.update(cast[ptr uint8](addr msg[0]), uint(len(msg)))
      sha256.update(cast[ptr uint8](addr msg[0]), uint(len(msg)))
      sha384.update(cast[ptr uint8](addr msg[0]), uint(len(msg)))
      sha512.update(cast[ptr uint8](addr msg[0]), uint(len(msg)))
      osha224.update(msg)
      osha256.update(msg)
      osha384.update(msg)
      osha512.update(msg)
    check:
      $sha224.finish() == stripSpaces(sdigest224[4])
      $sha256.finish() == stripSpaces(sdigest256[4])
      $sha384.finish() == stripSpaces(sdigest384[4])
      $sha512.finish() == stripSpaces(sdigest512[4])
      $osha224.finish() == stripSpaces(sdigest224[4])
      $osha256.finish() == stripSpaces(sdigest256[4])
      $osha384.finish() == stripSpaces(sdigest384[4])
      $osha512.finish() == stripSpaces(sdigest512[4])
    sha224.clear()
    sha256.clear()
    sha384.clear()
    sha512.clear()
    osha224.clear()
    osha256.clear()
    osha384.clear()
    osha512.clear()
    check:
      sha224.isFullZero() == true
      sha256.isFullZero() == true
      sha384.isFullZero() == true
      sha512.isFullZero() == true
      osha224.isFullZero() == true
      osha256.isFullZero() == true
      osha384.isFullZero() == true
      osha512.isFullZero() == true

  const shake128inputs = [
    "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3",
    ""
  ]

  const shake128digests = [
    """
      131AB8D2B594946B 9C81333F9BB6E0CE 75C3B93104FA3469 D3917457385DA037
      CF232EF7164A6D1E B448C8908186AD85 2D3F85A5CF28DA1A B6FE343817197846
      7F1C05D58C7EF38C 284C41F6C2221A76 F12AB1C040826602 50802294FB871802
      13FDEF5B0ECB7DF5 0CA1F8555BE14D32 E10F6EDCDE892C09 424B29F597AFC270
      C904556BFCB47A7D 40778D390923642B 3CBD0579E60908D5 A000C1D08B98EF93
      3F806445BF87F8B0 09BA9E94F7266122 ED7AC24E5E266C42 A82FA1BBEFB7B8DB
      0066E16A85E0493F 07DF4809AEC084A5 93748AC3DDE5A6D7 AAE1E8B6E5352B2D
      71EFBB47D4CAEED5 E6D633805D2D323E 6FD81B4684B93A26 77D45E7421C2C6AE
      A259B855A698FD7D 13477A1FE53E5A4A 6197DBEC5CE95F50 5B520BCD9570C4A8
      265A7E01F89C0C00 2C59BFEC6CD4A5C1 09258953EE5EE70C D577EE217AF21FA7
      0178F0946C9BF6CA 8751793479F6B537 737E40B6ED28511D 8A2D7E73EB75F8DA
      AC912FF906E0AB95 5B083BAC45A8E5E9 B744C8506F37E9B4 E749A184B30F43EB
      188D855F1B70D71F F3E50C537AC1B0F8 974F0FE1A6AD295B A42F6AEC74D123A7
      ABEDDE6E2C0711CA B36BE5ACB1A5A11A 4B1DB08BA6982EFC CD716929A7741CFC
      63AA4435E0B69A90 63E880795C3DC5EF 3272E11C497A91AC F699FEFEE206227A
      44C9FB359FD56AC0 A9A75A743CFF6862 F17D7259AB075216 C0699511643B6439
    """,
    """
      7F9C2BA4E88F827D 616045507605853E D73B8093F6EFBC88 EB1A6EACFA66EF26
      3CB1EEA988004B93 103CFB0AEEFD2A68 6E01FA4A58E8A363 9CA8A1E3F9AE57E2
      35B8CC873C23DC62 B8D260169AFA2F75 AB916A58D9749188 35D25E6A435085B2
      BADFD6DFAAC359A5 EFBB7BCC4B59D538 DF9A04302E10C8BC 1CBF1A0B3A5120EA
      17CDA7CFAD765F56 23474D368CCCA8AF 0007CD9F5E4C849F 167A580B14AABDEF
      AEE7EEF47CB0FCA9 767BE1FDA69419DF B927E9DF07348B19 6691ABAEB580B32D
      EF58538B8D23F877 32EA63B02B4FA0F4 873360E2841928CD 60DD4CEE8CC0D4C9
      22A96188D032675C 8AC850933C7AFF15 33B94C834ADBB69C 6115BAD4692D8619
      F90B0CDF8A7B9C26 4029AC185B70B83F 2801F2F4B3F70C59 3EA3AEEB613A7F1B
      1DE33FD75081F592 305F2E4526EDC096 31B10958F464D889 F31BA010250FDA7F
      1368EC2967FC84EF 2AE9AFF268E0B170 0AFFC6820B523A3D 917135F2DFF2EE06
      BFE72B3124721D4A 26C04E53A75E30E7 3A7A9C4A95D91C55 D495E9F51DD0B5E9
      D83C6D5E8CE803AA 62B8D654DB53D09B 8DCFF273CDFEB573 FAD8BCD45578BEC2
      E770D01EFDE86E72 1A3F7C6CCE275DAB E6E2143F1AF18DA7 EFDDC4C7B70B5E34
      5DB93CC936BEA323 491CCB38A388F546 A9FF00DD4E1300B9 B2153D2041D205B4
      43E41B45A653F2A5 C4492C1ADD544512 DDA2529833462B71 A41A45BE97290B6F
    """
  ]

  const shake256inputs = [
    "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3",
    ""
  ]

  const shake256digests = [
    """
      CD8A920ED141AA04 07A22D59288652E9 D9F1A7EE0C1E7C1C A699424DA84A904D
      2D700CAAE7396ECE 96604440577DA4F3 AA22AEB8857F961C 4CD8E06F0AE6610B
      1048A7F64E1074CD 629E85AD7566048E FC4FB500B486A330 9A8F26724C0ED628
      001A1099422468DE 726F1061D99EB9E9 3604D5AA7467D4B1 BD6484582A384317
      D7F47D750B8F5499 512BB85A226C4243 556E696F6BD072C5 AA2D9B69730244B5
      6853D16970AD817E 213E470618178001 C9FB56C54FEFA5FE E67D2DA524BB3B0B
      61EF0E9114A92CDB B6CCCB98615CFE76 E3510DD88D1CC28F F99287512F24BFAF
      A1A76877B6F37198 E3A641C68A7C42D4 5FA7ACC10DAE5F3C EFB7B735F12D4E58
      9F7A456E78C0F5E4 C4471FFFA5E4FA05 14AE974D8C264851 3B5DB494CEA84715
      6D277AD0E141C24C 7839064CD08851BC 2E7CA109FD4E251C 35BB0A04FB05B364
      FF8C4D8B59BC303E 25328C09A882E952 518E1A8AE0FF265D 61C465896973D749
      0499DC639FB8502B 39456791B1B6EC5B CC5D9AC36A6DF622 A070D43FED781F5F
      149F7B62675E7D1A 4D6DEC48C1C71645 86EAE06A51208C0B 791244D307726505
      C3AD4B26B6822377 257AA152037560A7 39714A3CA79BD605 547C9B78DD1F596F
      2D4F1791BC689A0E 9B799A37339C0427 5733740143EF5D2B 58B96A363D4E0807
      6A1A9D7846436E4D CA5728B6F760EEF0 CA92BF0BE5615E96 959D767197A0BEEB
    """,
    """
      46B9DD2B0BA88D13 233B3FEB743EEB24 3FCD52EA62B81B82 B50C27646ED5762F
      D75DC4DDD8C0F200 CB05019D67B592F6 FC821C49479AB486 40292EACB3B7C4BE
      141E96616FB13957 692CC7EDD0B45AE3 DC07223C8E92937B EF84BC0EAB862853
      349EC75546F58FB7 C2775C38462C5010 D846C185C15111E5 95522A6BCD16CF86
      F3D122109E3B1FDD 943B6AEC468A2D62 1A7C06C6A957C62B 54DAFC3BE87567D6
      77231395F6147293 B68CEAB7A9E0C58D 864E8EFDE4E1B9A4 6CBE854713672F5C
      AAAE314ED9083DAB 4B099F8E300F01B8 650F1F4B1D8FCF3F 3CB53FB8E9EB2EA2
      03BDC970F50AE554 28A91F7F53AC266B 28419C3778A15FD2 48D339EDE785FB7F
      5A1AAA96D313EACC 890936C173CDCD0F AB882C45755FEB3A ED96D477FF96390B
      F9A66D1368B208E2 1F7C10D04A3DBD4E 360633E5DB4B6026 01C14CEA737DB3DC
      F722632CC77851CB DDE2AAF0A33A07B3 73445DF490CC8FC1 E4160FF118378F11
      F0477DE055A81A9E DA57A4A2CFB0C839 29D310912F729EC6 CFA36C6AC6A75837
      143045D791CC85EF F5B21932F23861BC F23A52B5DA67EAF7 BAAE0F5FB1369DB7
      8F3AC45F8C4AC567 1D85735CDDDB09D2 B1E34A1FC066FF4A 162CB263D6541274
      AE2FCC865F618ABE 27C124CD8B074CCD 516301B91875824D 09958F341EF274BD
      AB0BAE3163398943 04E35877B0C28A9B 1FD166C796B9CC25 8A064A8F57E27F2A
    """
  ]

  # SHAKE-128 TESTS
  test "SHAKE-128 test vectors":
    var chk: array[512, uint8]
    var buf: array[32, uint8]
    var sctx = shake128()
    for t in 0..1:
      var msg = fromHex(stripSpaces(shake128inputs[t]))
      sctx.init()
      if t == 0:
        for i in 1..10:
          sctx.update(cast[ptr uint8](addr msg[0]), uint(len(msg)))
      sctx.xof()
      for i in 0..15:
        discard sctx.output(addr buf[0], uint(len(buf)))
        for j in 0..31:
          chk[i * 32 + j] = buf[j]
      check(toHex(chk) == stripSpaces(shake128digests[t]))
      sctx.clear()
      check sctx.isFullZero() == true

  # SHAKE-256 TEST
  test "SHAKE-256 test vectors":
    var chk: array[512, uint8]
    var buf: array[32, uint8]
    var sctx = shake256()
    for t in 0..1:
      var msg = fromHex(stripSpaces(shake256inputs[t]))
      sctx.init()
      if t == 0:
        for i in 1..10:
          sctx.update(cast[ptr uint8](addr msg[0]), uint(len(msg)))
      sctx.xof()
      for i in 0..15:
        discard sctx.output(addr buf[0], uint(len(buf)))
        for j in 0..31:
          chk[i * 32 + j] = buf[j]
      check(toHex(chk) == stripSpaces(shake256digests[t]))
      sctx.clear()
      check sctx.isFullZero() == true
