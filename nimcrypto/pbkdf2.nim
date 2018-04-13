#
#
#                    NimCrypto
#        (c) Copyright 2018 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements PBKDF2 (Password-Based Key Derivation Function 2)
## [https://tools.ietf.org/html/rfc2898#section-5.2]
## 
## Tests for PBKDF2-HMAC-SHA224/256/384/512 made according to
## [https://github.com/Anti-weakpasswords/PBKDF2-Test-Vectors/releases]

import hmac

proc pbkdf2*[T](ctx: var HMAC[T], password: string, salt: string, c: int,
                output: var openarray[byte], outlen: int = -1): int =
  ## Calculate PBKDF2 result using HMAC algorithm `ctx`.
  ## 
  ## ``ctx``      - HMAC[T] context
  ## ``password`` - password string
  ## ``salt``     - salt string
  ## ``c``        - number of iterations
  ## ``output``   - array of bytes where result will be stored.
  ## ``outlen``   - length of bytes to be stored (-1 default, whole `output`)
  ## 
  ## Returns number of bytes stored on success, or 0 on error.
  mixin init, update, finish
  var
    counter: array[4, byte]
    work: array[ctx.sizeDigest, byte]
    md: array[ctx.sizeDigest, byte]
    ctr: uint32
    glength: int
    olength: int
    bytesWrite: int
  if len(output) > 0xFFFF_FFFF: # (2^32 - 1)
    return 0
  let pwd = cast[seq[byte]](password)
  let slt = cast[seq[byte]](salt)
  ctr = 1
  glength = 0
  olength = if outlen == -1: len(output) else: outlen
  while glength < olength:
    counter[0] = byte((ctr shr 24) and 0xFF)
    counter[1] = byte((ctr shr 16) and 0xFF)
    counter[2] = byte((ctr shr 8) and 0xFF)
    counter[3] = byte(ctr and 0xFF)
    ctx.init(pwd)
    ctx.update(slt)
    ctx.update(counter)
    discard ctx.finish(md)
    work = md
    for i in 1..<c:
      ctx.init(pwd)
      ctx.update(md)
      discard ctx.finish(md)
      for k in 0..<len(work):
        work[k] = work[k] xor md[k]
    bytesWrite = min(olength - glength, int(ctx.sizeDigest))
    copyMem(addr output[glength], addr work[0], bytesWrite)
    glength += bytesWrite
    ctr = ctr + 1
  ctx.clear()
  result = glength
