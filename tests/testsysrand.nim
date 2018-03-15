import ../sysrand

when isMainModule:
  var buffer: array[1024, uint8]
  let count = randomBytes(addr buffer[0], 1024)
  doAssert(count == 1024)
