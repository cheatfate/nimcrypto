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
import hmac, utils
export hmac

proc pbkdf2*[T, M, N](ctx: var HMAC[T], password: openArray[M],
                      salt: openArray[N], c: int,
                      output: var openArray[byte]): int =
  ## Calculate PBKDF2 result using HMAC algorithm `ctx`.
  ##
  ## ``ctx``      - HMAC[T] context
  ## ``password`` - password string
  ## ``salt``     - salt string
  ## ``c``        - number of iterations
  ## ``output``   - array of bytes where result will be stored.
  ##
  ## Returns number of bytes stored on success, or 0 on error.
  mixin init, update, finish
  var
    counter: array[4, byte]
    work: array[int(ctx.sizeDigest), byte]
    md: array[int(ctx.sizeDigest), byte]
    ctr: uint32
    glength: int
    bytesWrite: int

  when not((M is byte) or (M is char)):
    {.fatal: "Choosen password type is not supported!".}

  when not((N is byte) or (N is char)):
    {.fatal: "Choosen salt type is not supported!".}

  when (sizeof(int) != 8) and (sizeof(int) != 4):
    {.fatal: "Choosen architecture is not supported!".}

  ctr = 1
  glength = 0
  let olength =
    when sizeof(int) == 8:
      min(len(output), int(0xFFFF_FFFF)) # 2^32 - 1
    else:
      len(output)

  while glength < olength:
    beStore32(counter, 0, ctr)
    ctx.init(password)
    ctx.update(salt)
    ctx.update(counter)
    discard ctx.finish(md)
    work = md
    for i in 1 ..< c:
      ctx.init(password)
      ctx.update(md)
      discard ctx.finish(md)
      for k in 0..<len(work):
        work[k] = work[k] xor md[k]

    bytesWrite = min(olength - glength, int(ctx.sizeDigest))
    copyMem(output, glength, work, 0, bytesWrite)
    glength = glength + bytesWrite
    ctr = ctr + 1
  ctx.clear()
  int(glength)

proc pbkdf2*[T, M, N](ctx: var HMAC[T], password: openArray[M],
                      salt: openArray[N], c: int,
                      output: var openArray[byte], outlen: int): int {.
     deprecated: "Use pbkdf2() with output.toOpenArray()", inline.} =
  ## Calculate PBKDF2 result using HMAC algorithm `ctx`.
  ##
  ## ``ctx``      - HMAC[T] context
  ## ``password`` - password string
  ## ``salt``     - salt string
  ## ``c``        - number of iterations
  ## ``output``   - array of bytes where result will be stored.
  ## ``outlen``   - length of bytes to be stored.
  ##
  ## Returns number of bytes stored on success, or 0 on error.
  if outlen == -1:
    pbkdf2(ctx, password, salt, c, output.toOpenArray(0, len(output) - 1))
  else:
    pbkdf2(ctx, password, salt, c, output.toOpenArray(0, outlen))

proc pbkdf2*[T, M](hashtype: typedesc, password: openArray[T],
                   salt: openArray[M], c: int,
                   outlen: int): seq[byte] {.inline.} =
  ## Calculate PBKDF2 result using HMAC[``hashtype``] algorithm.
  ##
  ## ``hashtype`` - hash algorithm which will be used in HMAC mode
  ## ``password`` - password string
  ## ``salt``     - salt string
  ## ``c``        - number of iterations
  ## ``outlen``   - length of bytes to be stored.
  ##
  ## Returns sequence of bytes.
  var res: seq[byte]
  if outlen > 0:
    var ctx: HMAC[hashtype]
    res.setLen(outlen)
    discard pbkdf2(ctx, password, salt, c, res)
  res
