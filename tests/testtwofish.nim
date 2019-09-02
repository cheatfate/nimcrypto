import nimcrypto/twofish, nimcrypto/utils
import unittest

when defined(nimHasUsed): {.used.}

## Tests made according to official test vectors
## [https://www.schneier.com/code/ecb_ival.txt].

proc test[T](n: int): seq[uint8] =
  var keysize = n div 8
  var blocksize = 128 div 8
  var list = newSeq[seq[uint8]](60)
  var key: seq[uint8]
  list[0] = newSeq[uint8](keysize)
  list[1] = newSeq[uint8](keysize)
  var k = 0
  for i in 0..48:
    var ctx = T()
    key = list[k]
    var data = list[k + 1][0..<blocksize]
    var check = data
    ctx.init(addr key[0])
    ctx.encrypt(addr data[0], addr data[0])
    var enc = data
    ctx.decrypt(addr enc[0], addr enc[0])
    doAssert(enc == check)
    ctx.clear()
    doAssert(ctx.isFullZero() == true)
    if blocksize != keysize:
      list[k + 2] = data & list[k + 1][0..<(keysize - blocksize)]
    else:
      list[k + 2] = data
    inc(k)
    result = data

suite "Twofish Tests":
  test "TWOFISH-128/192/256 block sizes":
    var ctx128: twofish128
    var ctx192: twofish192
    var ctx256: twofish256
    check:
      ctx128.sizeBlock == 16
      ctx192.sizeBlock == 16
      ctx256.sizeBlock == 16
      twofish128.sizeBlock == 16
      twofish192.sizeBlock == 16
      twofish256.sizeBlock == 16
  test "TWOFISH-128/192/256 key sizes":
    var ctx128: twofish128
    var ctx192: twofish192
    var ctx256: twofish256
    check:
      ctx128.sizeKey == 16
      ctx192.sizeKey == 24
      ctx256.sizeKey == 32
      twofish128.sizeKey == 16
      twofish192.sizeKey == 24
      twofish256.sizeKey == 32
  test "TWOFISH-128":
    var res = test[twofish128](128)
    check(toHex(res) == "5D9D4EEFFA9151575524F115815A12E0")
  test "TWOFISH-192":
    var res = test[twofish192](192)
    check(toHex(res) == "E75449212BEEF9F4A390BD860A640941")
  test "TWOFISH-256":
    var res = test[twofish256](256)
    check(toHex(res) == "37FE26FF1CF66175F5DDF4C33B97A205")
