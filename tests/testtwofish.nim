import ../twofish, ../utils

when isMainModule:
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
      if blocksize != keysize:
        list[k + 2] = data & list[k + 1][0..<(keysize - blocksize)]
      else:
        list[k + 2] = data
      inc(k)
      result = data

  var r128 = test[twofish128](128)
  var r192 = test[twofish192](192)
  var r256 = test[twofish256](256)
  doAssert(toHex(r128) == "5D9D4EEFFA9151575524F115815A12E0")
  doAssert(toHex(r192) == "E75449212BEEF9F4A390BD860A640941")
  doAssert(toHex(r256) == "37FE26FF1CF66175F5DDF4C33B97A205")
