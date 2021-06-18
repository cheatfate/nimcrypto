#
#
#                    NimCrypto
#          (c) Copyright 2020 Andri Lim
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#
import utils, hmac, pbkdf2
export hmac

## This module implements
## The scrypt Password-Based Key Derivation Function
## https://tools.ietf.org/html/rfc7914

proc salsaXor(tmp: var openArray[uint32],
  src: openArray[uint32], srco: int, dest: var openArray[uint32], dsto: int) =
  ## salsaXor applies Salsa20/8 to the XOR of 16 numbers from tmp and in,
  ## and puts the result into both tmp and out.

  # no macros policy
  let
    w0 = tmp[0] xor src[0 + srco]
    w1 = tmp[1] xor src[1 + srco]
    w2 = tmp[2] xor src[2 + srco]
    w3 = tmp[3] xor src[3 + srco]
    w4 = tmp[4] xor src[4 + srco]
    w5 = tmp[5] xor src[5 + srco]
    w6 = tmp[6] xor src[6 + srco]
    w7 = tmp[7] xor src[7 + srco]
    w8 = tmp[8] xor src[8 + srco]
    w9 = tmp[9] xor src[9 + srco]
    w10 = tmp[10] xor src[10 + srco]
    w11 = tmp[11] xor src[11 + srco]
    w12 = tmp[12] xor src[12 + srco]
    w13 = tmp[13] xor src[13 + srco]
    w14 = tmp[14] xor src[14 + srco]
    w15 = tmp[15] xor src[15 + srco]

  var
    x0 = w0
    x1 = w1
    x2 = w2
    x3 = w3
    x4 = w4
    x5 = w5
    x6 = w6
    x7 = w7
    x8 = w8
    x9 = w9
    x10 = w10
    x11 = w11
    x12 = w12
    x13 = w13
    x14 = w14
    x15 = w15

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

  x0  += w0;  x1  +=  w1; x2  +=  w2; x3  +=  w3
  x4  += w4;  x5  +=  w5; x6  +=  w6; x7  +=  w7
  x8  += w8;  x9  +=  w9; x10 += w10; x11 += w11
  x12 += w12; x13 += w13; x14 += w14; x15 += w15

  dest[0  + dsto] =  x0; dest[1  + dsto] =  x1
  dest[2  + dsto] =  x2; dest[3  + dsto] =  x3
  dest[4  + dsto] =  x4; dest[5  + dsto] =  x5
  dest[6  + dsto] =  x6; dest[7  + dsto] =  x7
  dest[8  + dsto] =  x8; dest[9  + dsto] =  x9
  dest[10 + dsto] = x10; dest[11 + dsto] = x11
  dest[12 + dsto] = x12; dest[13 + dsto] = x13
  dest[14 + dsto] = x14; dest[15 + dsto] = x15

  tmp[0]  =  x0; tmp[1]  = x1;  tmp[2]  =  x2
  tmp[3]  =  x3; tmp[4]  = x4;  tmp[5]  =  x5
  tmp[6]  =  x6; tmp[7]  = x7;  tmp[8]  =  x8
  tmp[9]  =  x9; tmp[10] = x10; tmp[11] = x11
  tmp[12] = x12; tmp[13] = x13; tmp[14] = x14
  tmp[15] = x15

proc blockMix(tmp: var openArray[uint32], src: openArray[uint32], srco: int,
              dest: var openArray[uint32], dsto: int, r: int) =
  let
    r16  = r*16
    r2_1 = 2*r-1
  var
    i16 = srco
    i8 = dsto
  copyMem(tmp, 0, src, r2_1*16+srco, 16)
  for i in countup(0, r2_1, 2):
    salsaXor(tmp, src, i16, dest, i8)
    salsaXor(tmp, src, i16+16, dest, i8+r16)
    inc(i16, 32)
    inc(i8, 16)

func integer(b: openArray[uint32], boff, r: int): uint64 =
  let j = (2*r - 1) * 16 + boff
  result = uint64(b[j]) or (uint64(b[j+1]) shl 32)

proc blockXor(dst: var openArray[uint32], dsto: int,
              src: openArray[uint32], srco: int, n: int) =

  ## blockXor XORs numbers from dst with n numbers from src.
  for i in 0 ..< n:
    dst[i+dsto] = dst[i+dsto] xor src[i+srco]

proc smix(b: var openArray[byte], boffset, r, N: int,
          xyv: var openArray[uint32], voffset: int) =
  let
    r32 = r * 32
    N_1 = N - 1

  template x: untyped = xyv
  template v: untyped = xyv
  template y: untyped = xyv
  template yoffset: untyped = r32

  var
    # tmp: store xor'ed value for next step
    tmp: array[16, uint32]
    j = boffset

  for i in 0 ..< r32:
    x[i] = leLoad32(b, j)
    inc(j, 4)

  var n = voffset
  for i in countup(0, N_1, 2):
    # x[n] is an alias to v
    copyMem(v, n, x, 0, r32)
    blockMix(tmp, x, 0, y, yoffset, r)
    inc(n, r32)

    copyMem(v, n, y, yoffset, r32)
    blockMix(tmp, y, yoffset, x, 0, r)
    inc(n, r32)

  for i in countup(0, N_1, 2):
    j = int(integer(x, 0, r) and uint64(N_1))
    blockXor(x, 0, v, j*r32+voffset, r32)
    blockMix(tmp, x, 0, y, yoffset, r)

    j = int(integer(y, yoffset, r) and uint64(N_1))
    blockXor(y, yoffset, v, j*r32+voffset, r32)
    blockMix(tmp, y, yoffset, x, 0, r)

  j = boffset
  for i in 0 ..< r32:
    leStore32(b, j, x[i])
    inc(j, 4)

func validateParam(N, r, p: int): bool =
  # this function does not prevent DOS attack
  # in case of using huge number
  if N <= 1 or (N and (N-1)) != 0:
    # N must be > 1 and a power of 2
    return false

  const
    maxInt = high(int64)
    maxIntd128 = maxInt div 128
    maxIntd256 = maxInt div 256

  let
    badParam1 = (uint64(r) * uint64(p)) >= uint64(1 shl 30)
    badParam2 = r > maxIntd128 div p
    badParam3 = r > maxIntd256
    badParam4 = N > maxIntd128 div r

  if badParam1 or badParam2 or badParam3 or badParam4:
    # parameters are too large
    return false

  result = true

# scrypt derives a key from the password, salt, and cost parameters, returning
# a byte slice of length keyLen that can be used as cryptographic key.
#
# N is a CPU/memory cost parameter, which must be a power of two greater than 1.
# r and p must satisfy r * p < 2^30. If the parameters do not satisfy the
# limits, the function return zero.
#
# Returns number of bytes stored on success, or 0 on error.
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
func scrypt*[T, M](password: openArray[T], salt: openArray[M],
             N, r, p: int, xyv: var openArray[uint32],
             b, output: var openArray[byte]): int =

  when not((M is byte) or (M is char)):
    {.fatal: "Choosen password type is not supported!".}

  when not((T is byte) or (T is char)):
    {.fatal: "Choosen salt type is not supported!".}

  if not validateParam(N, r, p):
    return 0

  let
    r32  = r*32
    r64  = r32*2
    r128 = r64*2

  if b.len < p*r128:
    return 0

  if xyv.len < r32*(N+2):
    return 0

  var ctx: HMAC[sha256]
  if ctx.pbkdf2(password, salt, 1, b) == 0:
    return 0

  var n = 0
  for i in 0 ..< p:
    smix(b, n, r, N, xyv, r64)
    inc(n, r128)

  ctx.pbkdf2(password, b, 1, output)

# because of NimCrypto no alloc policy,
# users of scrypt must provide their own `xyv` and `b` array.
# scryptCalc will return how much element needed.
# return value -> (xyv.len of uint32s, b.len of bytes)
func scryptCalc*(N, r, p: int): (int, int) =
  result = ((r*32*(N+2)), (p*r*128))
