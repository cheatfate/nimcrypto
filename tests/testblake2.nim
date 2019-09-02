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
        b256p.finish(check2a)
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
        b512p.finish(check2a)

        var check2 = toHex(check2a)
        check:
          expect == check1
          expect == check2

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
