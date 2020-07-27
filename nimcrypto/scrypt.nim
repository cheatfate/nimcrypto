import macros, nimcrypto/[utils, pbkdf2]

macro repInc(n: static[int], body: untyped) =
  # repeat body as much as `n` and replace
  # any `z` in body with an int via template
  var x = genSym(nskTemplate, "x")
  var z = newIdentNode("z")
  result = newStmtList()
  result.add quote do:
    template `x`(`z`: untyped) = `body`
  for i in 0..<n:
    result.add quote do: `x`(`i`)

proc salsaXor(tmp: var openArray[uint32],
  src: openArray[uint32], srco: int, dest: var openArray[uint32], dsto: int) =
  # salsaXor applies Salsa20/8 to the XOR of 16 numbers from tmp and in,
  # and puts the result into both tmp and out.

  repInc(16):
    # we need the {.inject.} because it was generated via template
    var `w z` {.inject.} = tmp[z] xor src[z + srco]
    var `x z` {.inject.} = `w z`

  template R(x, a, b: untyped) =
    x = x xor ROL(a, b)

  for i in 0 ..< 4:
    R(x4, x0+x12,  7); R(x8, x4+x0, 9)
    R(x12, x8+x4, 13); R(x0, x12+x8, 18)

    R(x9,  x5+x1,  7); R(x13, x9+x5, 9)
    R(x1, x13+x9, 13); R(x5, x1+x13, 18)

    R(x14, x10+x6, 7); R(x2, x14+x10, 9)
    R(x6, x2+x14, 13); R(x10, x6+x2, 18)

    R(x3, x15+x11, 7); R(x7, x3+x15, 9)
    R(x11, x7+x3, 13); R(x15, x11+x7, 18)

    R(x1, x0+x3,  7);  R(x2, x1+x0, 9)
    R(x3, x2+x1, 13);  R(x0, x3+x2, 18)

    R(x6, x5+x4,  7);  R(x7, x6+x5, 9)
    R(x4, x7+x6, 13);  R(x5, x4+x7, 18)

    R(x11, x10+x9, 7); R(x8, x11+x10, 9)
    R(x9, x8+x11, 13); R(x10, x9+x8, 18)

    R(x12, x15+x14,  7); R(x13, x12+x15, 9)
    R(x14, x13+x12, 13); R(x15, x14+x13, 18)

  repInc(16):
    `x z` = `x z` + `w z`
    dest[z + dsto] = `x z`
    tmp[z] = `x z`

proc blockMix(tmp: var openArray[uint32], src: openArray[uint32],
              dest: var openArray[uint32], r: int) =
  let
    r16  = r*16
    r2_1 = 2*r-1
  var i16, i8: int
  copyMem(tmp, 0, src, r2_1*16, 16)
  for i in countup(0, r2_1, 2):
    salsaXor(tmp, src, i16, dest, i8)
    salsaXor(tmp, src, i16+16, dest, i8+r16)
    inc(i16, 32)
    inc(i8, 16)

func integer(b: openArray[uint32], r: int): uint64 =
  let j = (2*r - 1) * 16
  result = uint64(b[j]) or (uint64(b[j+1]) shl 32)

proc blockXor(dst: var openArray[uint32],
              src: openArray[uint32], srco: int, n: int) =

  # blockXor XORs numbers from dst with n numbers from src.
  for i in 0 ..< n:
    dst[i] = dst[i] xor src[i+srco]

proc smix(b: var openArray[byte], boffset, r, N: int,
          v, xy: var openArray[uint32]) =
  let
    r32 = r * 32
    N_1 = N - 1
  template x: untyped = xy
  template y: untyped = xy.toOpenArray(r32, xy.len-1)

  var
    # tmp: store xor'ed value for next step
    tmp: array[16, uint32]
    j = boffset

  for i in 0 ..< r32:
    x[i] = leLoad32(b, j)
    inc(j, 4)

  var n = 0
  for i in countup(0, N_1, 2):
    copyMem(v, n, x, 0, r32)
    blockMix(tmp, x, y, r)
    inc(n, r32)

    copyMem(v, n, x, r32, r32)
    blockMix(tmp, y, x, r)
    inc(n, r32)

  for i in countup(0, N_1, 2):
    j = int(integer(x, r) and uint64(N_1))
    blockXor(x, v, j*r32, r32)
    blockMix(tmp, x, y, r)

    j = int(integer(y, r) and uint64(N_1))
    blockXor(y, v, j*r32, r32)
    blockMix(tmp, y, x, r)

  j = boffset
  for i in 0 ..< r32:
    leStore32(b, j, x[i])
    inc(j, 4)

# Key derives a key from the password, salt, and cost parameters, returning
# a byte slice of length keyLen that can be used as cryptographic key.
#
# N is a CPU/memory cost parameter, which must be a power of two greater than 1.
# r and p must satisfy r * p < 2^30. If the parameters do not satisfy the
# limits, the function raises an exception.
#
# For example, you can get a derived key for e.g. AES-256 (which needs a
# 32-byte key) by doing:
#
#    dk = scrypt(some_password, salt, 32768, 8, 1, 32)
#
# The recommended parameters for interactive logins as of 2017 are N=32768, r=8
# and p=1. The parameters N, r, and p should be increased as memory latency and
# CPU parallelism increases; consider setting N to the highest power of 2 you
# can derive within 100 milliseconds. Remember to get a good random salt.
func validateParam(N, r, p: int) {.raises: ValueError.} =
  if N <= 1 or (N and (N-1)) != 0:
    raise newException(ValueError, "scrypt: N must be > 1 and a power of 2")

  const
    maxInt = high(int64)
    maxIntd128 = maxInt div 128
    maxIntd256 = maxInt div 256

  let
    badParam1 = uint64(r)*uint64(p) >= 1 shl 30
    badParam2 = r > maxIntd128 div p
    badParam3 = r > maxIntd256
    badParam4 = N > maxIntd128 div r

  if badParam1 or badParam2 or badParam3 or badParam4:
    raise newException(ValueError, "scrypt: parameters are too large")

func scrypt*(password, salt: openArray[byte],
             N, r, p, keyLen: int): seq[byte] {.raises: ValueError.} =
  validateParam(N, r, p)
  let
    r32  = r*32
    r64  = r32*2
    r128 = r64*2

  var
    x = newSeq[uint32](r64 + r32*N) # xy + v in one alloc
    b = sha256.pbkdf2(password, salt, 1, p*r128)
    n = 0

  for i in 0 ..< p:
    smix(b, n, r, N, x.toOpenArray(r64, x.len-1), x)
    inc(n, r128)

  sha256.pbkdf2(password, b, 1, keyLen)

func scrypt*(password, salt: string,
             N, r, p, keyLen: int): seq[byte] {.raises: ValueError.} =
  scrypt(password.toOpenArrayByte(0, password.len-1),
    salt.toOpenArrayByte(0, salt.len-1), N, r, p, keyLen)
