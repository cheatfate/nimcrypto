import nimcrypto/hash, nimcrypto/blake2, nimcrypto/utils
import unittest, json

when defined(nimHasUsed): {.used.}

suite "BLAKE2B/BLAKE2S Tests":

  test "BLAKE2B/BLAKE2S 224/256/384/512 block sizes":
    var b224: blake2_224
    var b256: blake2_256
    var b384: blake2_384
    var b512: blake2_512
    check:
      b224.sizeBlock == 64
      b256.sizeBlock == 64
      b384.sizeBlock == 128
      b512.sizeBlock == 128
      blake2_224.sizeBlock == 64
      blake2_256.sizeBlock == 64
      blake2_384.sizeBlock == 128
      blake2_512.sizeBlock == 128

  test "BLAKE2B/BLAKE2S 224/256/384/512 digest sizes":
    var b224: blake2_224
    var b256: blake2_256
    var b384: blake2_384
    var b512: blake2_512
    check:
      b224.sizeDigest == 28
      b256.sizeDigest == 32
      b384.sizeDigest == 48
      b512.sizeDigest == 64
      blake2_224.sizeDigest == 28
      blake2_256.sizeDigest == 32
      blake2_384.sizeDigest == 48
      blake2_512.sizeDigest == 64

  test "BLAKE2S-256 test json-vectors":
    var tj = parseFile("tests/blake2-kat.json")
    for item in tj.items():
      if item["hash"].str == "blake2s":
        var b256p: blake2_256
        var b256t: blake2_256
        var inpstr = item["in"].str
        var keystr = item["key"].str
        var expectstr = item["out"].str
        var inp = fromHex(stripSpaces(inpstr))
        var key = fromHex(stripSpaces(keystr))
        var expectarr = fromHex(stripSpaces(expectstr))
        var expect = toHex(expectarr)
        var check2a: array[32, byte]

        if len(key) > 0:
          b256p.init(addr key[0], uint(len(key)))
        else:
          b256p.init()
        b256t.init(key)
        if len(inp) > 0:
          b256p.update(addr inp[0], uint(len(inp)))
        else:
          b256p.update(nil, 0)
        b256t.update(inp)
        var check1 = $b256t.finish()
        discard b256p.finish(check2a)
        var check2 = toHex(check2a)
        b256t.clear()
        b256p.clear()
        check:
          expect == check1
          expect == check2
          b256t.isFullZero() == true
          b256p.isFullZero() == true

  test "BLAKE2B-512 test json-vectors":
    var tj = parseFile("tests/blake2-kat.json")
    for item in tj.items():
      if item["hash"].str == "blake2b":
        var b512p: blake2_512
        var b512t: blake2_512
        var inpstr = item["in"].str
        var keystr = item["key"].str
        var expectstr = item["out"].str
        var inp = fromHex(stripSpaces(inpstr))
        var key = fromHex(stripSpaces(keystr))
        var expectarr = fromHex(stripSpaces(expectstr))
        var expect = toHex(expectarr)
        var check2a: array[64, byte]
        if len(key) > 0:
          b512p.init(addr key[0], uint(len(key)))
        else:
          b512p.init()
        b512t.init(key)
        if len(inp) > 0:
          b512p.update(addr inp[0], uint(len(inp)))
        else:
          b512p.update(nil, 0)
        b512t.update(inp)
        var check1 = $b512t.finish()
        discard b512p.finish(check2a)
        var check2 = toHex(check2a)
        b512t.clear()
        b512p.clear()
        check:
          expect == check1
          expect == check2
          b512t.isFullZero() == true
          b512p.isFullZero() == true

  test "BLAKE2S-256 one liner json-vectors":
    var tj = parseFile("tests/blake2-kat.json")
    for item in tj.items():
      if item["hash"].str == "blake2s" and item["key"].str == "":
        var inpstr = item["in"].str
        var expstr = item["out"].str
        var inp = fromHex(stripSpaces(inpstr))
        var expectarr = fromHex(stripSpaces(expstr))
        var expect = toHex(expectarr)
        var check0 = $blake2_256.digest(inp)
        check:
          check0 == expect

  test "BLAKE2B-512 one liner json-vectors":
    var tj = parseFile("tests/blake2-kat.json")
    for item in tj.items():
      if item["hash"].str == "blake2b" and item["key"].str == "":
        var inpstr = item["in"].str
        var expstr = item["out"].str
        var inp = fromHex(stripSpaces(inpstr))
        var expectarr = fromHex(stripSpaces(expstr))
        var expect = toHex(expectarr)
        var check0 = $blake2_512.digest(inp)
        check:
          check0 == expect

  test "BLAKE2S-256 empty update() test":
    const
      msg = "616263"
      digest = """
        508C5E8C327C14E2E1A72BA34EEB452F37458B209ED63A294D999B4C86675982
      """
    var emptymsg: seq[byte]
    var datamsg = fromHex(stripSpaces(msg))
    var edigest = fromHex(stripSpaces(digest))
    var ctx1, ctx2: blake2_256
    ctx1.init()
    ctx2.init()
    ctx1.update(datamsg)
    ctx2.update(addr datamsg[0], uint(len(datamsg)))
    ctx1.update(emptymsg)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  test "BLAKE2B-512 empty update() test":
    const
      msg = "616263"
      digest = """
        BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D1
        7D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923
      """
    var emptymsg: seq[byte]
    var datamsg = fromHex(stripSpaces(msg))
    var edigest = fromHex(stripSpaces(digest))
    var ctx1, ctx2: blake2_512
    ctx1.init()
    ctx2.init()
    ctx1.update(datamsg)
    ctx2.update(addr datamsg[0], uint(len(datamsg)))
    ctx1.update(emptymsg)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  test "BLAKE2S-256 compile-time test":
    const
      vectors = [
        "",
        "00",
        "0001",
        "000102",
        "00010203",
        "0001020304",
        "000102030405",
        "00010203040506"
      ]
      digests = [
        "69217A3079908094E11121D042354A7C1F55B6482CA1A51E1B250DFD1ED0EEF9",
        "E34D74DBAF4FF4C6ABD871CC220451D2EA2648846C7757FBAAC82FE51AD64BEA",
        "DDAD9AB15DAC4549BA42F49D262496BEF6C0BAE1DD342A8808F8EA267C6E210C",
        "E8F91C6EF232A041452AB0E149070CDD7DD1769E75B3A5921BE37876C45C9900",
        "0CC70E00348B86BA2944D0C32038B25C55584F90DF2304F55FA332AF5FB01E20",
        "EC1964191087A4FE9DF1C795342A02FFC191A5B251764856AE5B8B5769F0C6CD",
        "E1FA51618D7DF4EB70CF0D5A9E906F806E9D19F7F4F01E3B621288E4120405D6",
        "598001FAFBE8F94EC66DC827D012CFCBBA2228569F448E89EA2208C8BF769293"
      ]
      keys = [
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
      ]
      kdigests = [
        "48A8997DA407876B3D79C0D92325AD3B89CBB754D86AB71AEE047AD345FD2C49",
        "40D15FEE7C328830166AC3F918650F807E7E01E177258CDC0A39B11F598066F1",
        "6BB71300644CD3991B26CCD4D274ACD1ADEAB8B1D7914546C1198BBE9FC9D803",
        "1D220DBE2EE134661FDF6D9E74B41704710556F2F6E5A091B227697445DBEA6B",
        "F6C3FBADB4CC687A0064A5BE6E791BEC63B868AD62FBA61B3757EF9CA52E05B2",
        "49C1F21188DFD769AEA0E911DD6B41F14DAB109D2B85977AA3088B5C707E8598",
        "FDD8993DCD43F696D44F3CEA0FF35345234EC8EE083EB3CADA017C7F78C17143",
        "E6C8125637438D0905B749F46560AC89FD471CF8692E28FAB982F73F019B83A9"
      ]

    proc keyDigest(a: openArray[byte]): string =
      var ctx: blake2_256
      ctx.init(fromHex(stripSpaces(keys[0])))
      ctx.update(a)
      result = $ctx.finish()

    const
      check2561 = $blake2_256.digest(fromHex(vectors[0]))
      check2562 = $blake2_256.digest(fromHex(vectors[1]))
      check2563 = $blake2_256.digest(fromHex(vectors[2]))
      check2564 = $blake2_256.digest(fromHex(vectors[3]))
      check2565 = $blake2_256.digest(fromHex(vectors[4]))
      check2566 = $blake2_256.digest(fromHex(vectors[5]))
      check2567 = $blake2_256.digest(fromHex(vectors[6]))
      check2568 = $blake2_256.digest(fromHex(vectors[7]))
      kcheck2561 = keyDigest(fromHex(vectors[0]))
      kcheck2562 = keyDigest(fromHex(vectors[1]))
      kcheck2563 = keyDigest(fromHex(vectors[2]))
      kcheck2564 = keyDigest(fromHex(vectors[3]))
      kcheck2565 = keyDigest(fromHex(vectors[4]))
      kcheck2566 = keyDigest(fromHex(vectors[5]))
      kcheck2567 = keyDigest(fromHex(vectors[6]))
      kcheck2568 = keyDigest(fromHex(vectors[7]))

    check:
      check2561 == digests[0]
      check2562 == digests[1]
      check2563 == digests[2]
      check2564 == digests[3]
      check2565 == digests[4]
      check2566 == digests[5]
      check2567 == digests[6]
      check2568 == digests[7]
      kcheck2561 == kdigests[0]
      kcheck2562 == kdigests[1]
      kcheck2563 == kdigests[2]
      kcheck2564 == kdigests[3]
      kcheck2565 == kdigests[4]
      kcheck2566 == kdigests[5]
      kcheck2567 == kdigests[6]
      kcheck2568 == kdigests[7]

  test "BLAKE2B-512 compile-time test":
    const
      vectors = [
        "",
        "00",
        "0001",
        "000102",
        "00010203",
        "0001020304",
        "000102030405",
        "00010203040506"
      ]
      digests = [
        """786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419
           D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE""",
        """2FA3F686DF876995167E7C2E5D74C4C7B6E48F8068FE0E44208344D480F7904C
           36963E44115FE3EB2A3AC8694C28BCB4F5A0F3276F2E79487D8219057A506E4B""",
        """1C08798DC641ABA9DEE435E22519A4729A09B2BFE0FF00EF2DCD8ED6F8A07D15
           EAF4AEE52BBF18AB5608A6190F70B90486C8A7D4873710B1115D3DEBBB4327B5""",
        """40A374727302D9A4769C17B5F409FF32F58AA24FF122D7603E4FDA1509E919D4
           107A52C57570A6D94E50967AEA573B11F86F473F537565C66F7039830A85D186""",
        """77DDF4B14425EB3D053C1E84E3469D92C4CD910ED20F92035E0C99D8A7A86CEC
           AF69F9663C20A7AA230BC82F60D22FB4A00B09D3EB8FC65EF547FE63C8D3DDCE""",
        """CBAA0BA7D482B1F301109AE41051991A3289BC1198005AF226C5E4F103B66579
           F461361044C8BA3439FF12C515FB29C52161B7EB9C2837B76A5DC33F7CB2E2E8""",
        """F95D45CF69AF5C2023BDB505821E62E85D7CAEDF7BEDA12C0248775B0C88205E
           EB35AF3A90816F6608CE7DD44EC28DB1140614E1DDEBF3AA9CD1843E0FAD2C36""",
        """8F945BA700F2530E5C2A7DF7D5DCE0F83F9EFC78C073FE71AE1F88204A4FD1CF
           70A073F5D1F942ED623AA16E90A871246C90C45B621B3401A5DDBD9DF6264165"""
      ]

      keys = [
        """000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
           202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"""
      ]

      kdigests = [
        """10EBB67700B1868EFB4417987ACF4690AE9D972FB7A590C2F02871799AAA4786
           B5E996E8F0F4EB981FC214B005F42D2FF4233499391653DF7AEFCBC13FC51568""",
        """961F6DD1E4DD30F63901690C512E78E4B45E4742ED197C3C5E45C549FD25F2E4
           187B0BC9FE30492B16B0D0BC4EF9B0F34C7003FAC09A5EF1532E69430234CEBD""",
        """DA2CFBE2D8409A0F38026113884F84B50156371AE304C4430173D08A99D9FB1B
           983164A3770706D537F49E0C916D9F32B95CC37A95B99D857436F0232C88A965""",
        """33D0825DDDF7ADA99B0E7E307104AD07CA9CFD9692214F1561356315E784F3E5
           A17E364AE9DBB14CB2036DF932B77F4B292761365FB328DE7AFDC6D8998F5FC1""",
        """BEAA5A3D08F3807143CF621D95CD690514D0B49EFFF9C91D24B59241EC0EEFA5
           F60196D407048BBA8D2146828EBCB0488D8842FD56BB4F6DF8E19C4B4DAAB8AC""",
        """098084B51FD13DEAE5F4320DE94A688EE07BAEA2800486689A8636117B46C1F4
           C1F6AF7F74AE7C857600456A58A3AF251DC4723A64CC7C0A5AB6D9CAC91C20BB""",
        """6044540D560853EB1C57DF0077DD381094781CDB9073E5B1B3D3F6C7829E1206
           6BBACA96D989A690DE72CA3133A83652BA284A6D62942B271FFA2620C9E75B1F""",
        """7A8CFE9B90F75F7ECB3ACC053AAED6193112B6F6A4AEEB3F65D3DE541942DEB9
           E2228152A3C4BBBE72FC3B12629528CFBB09FE630F0474339F54ABF453E2ED52"""
      ]

    proc keyDigest(a: openArray[byte]): string =
      var ctx: blake2_512
      ctx.init(fromHex(stripSpaces(keys[0])))
      ctx.update(a)
      result = $ctx.finish()

    const
      check5121 = $blake2_512.digest(fromHex(vectors[0]))
      check5122 = $blake2_512.digest(fromHex(vectors[1]))
      check5123 = $blake2_512.digest(fromHex(vectors[2]))
      check5124 = $blake2_512.digest(fromHex(vectors[3]))
      check5125 = $blake2_512.digest(fromHex(vectors[4]))
      check5126 = $blake2_512.digest(fromHex(vectors[5]))
      check5127 = $blake2_512.digest(fromHex(vectors[6]))
      check5128 = $blake2_512.digest(fromHex(vectors[7]))
      kcheck5121 = keyDigest(fromHex(vectors[0]))
      kcheck5122 = keyDigest(fromHex(vectors[1]))
      kcheck5123 = keyDigest(fromHex(vectors[2]))
      kcheck5124 = keyDigest(fromHex(vectors[3]))
      kcheck5125 = keyDigest(fromHex(vectors[4]))
      kcheck5126 = keyDigest(fromHex(vectors[5]))
      kcheck5127 = keyDigest(fromHex(vectors[6]))
      kcheck5128 = keyDigest(fromHex(vectors[7]))

    check:
      check5121 == stripSpaces(digests[0])
      check5122 == stripSpaces(digests[1])
      check5123 == stripSpaces(digests[2])
      check5124 == stripSpaces(digests[3])
      check5125 == stripSpaces(digests[4])
      check5126 == stripSpaces(digests[5])
      check5127 == stripSpaces(digests[6])
      check5128 == stripSpaces(digests[7])
      kcheck5121 == stripSpaces(kdigests[0])
      kcheck5122 == stripSpaces(kdigests[1])
      kcheck5123 == stripSpaces(kdigests[2])
      kcheck5124 == stripSpaces(kdigests[3])
      kcheck5125 == stripSpaces(kdigests[4])
      kcheck5126 == stripSpaces(kdigests[5])
      kcheck5127 == stripSpaces(kdigests[6])
      kcheck5128 == stripSpaces(kdigests[7])
