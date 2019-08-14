#
#
#                    NimCrypto
#        (c) Copyright 2018 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements SHA3 (Secure Hash Algorithm 3) set of cryptographic
## hash functions designed by Guido Bertoni, Joan Daemen, Michaël Peeters and
## Gilles Van Assche.
##
## This module supports SHA3-224/256/384/512 and SHAKE-128/256.
##
## Tests for SHA3-225/256/384/512 made according to
## [https://www.di-mgt.com.au/sha_testvectors.html].
## Test for SHAKE-128/256 made according to
## [https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values#aHashing]
## 0bit and 1600bit test vectors used.

import hash, utils

{.deadCodeElim:on.}

const RNDC = [
  0x0000000000000001'u64, 0x0000000000008082'u64, 0x800000000000808A'u64,
  0x8000000080008000'u64, 0x000000000000808B'u64, 0x0000000080000001'u64,
  0x8000000080008081'u64, 0x8000000000008009'u64, 0x000000000000008A'u64,
  0x0000000000000088'u64, 0x0000000080008009'u64, 0x000000008000000A'u64,
  0x000000008000808B'u64, 0x800000000000008B'u64, 0x8000000000008089'u64,
  0x8000000000008003'u64, 0x8000000000008002'u64, 0x8000000000000080'u64,
  0x000000000000800A'u64, 0x800000008000000A'u64, 0x8000000080008081'u64,
  0x8000000000008080'u64, 0x0000000080000001'u64, 0x8000000080008008'u64
]

type
  KeccakKind* = enum
    Sha3, Keccak, Shake

  KeccakContext*[bits: static[int],
                 kind: static[KeccakKind]] = object
    q: array[25, uint64]
    pt: int

  keccak224* = KeccakContext[224, Keccak]
  keccak256* = KeccakContext[256, Keccak]
  keccak384* = KeccakContext[384, Keccak]
  keccak512* = KeccakContext[512, Keccak]
  sha3_224* = KeccakContext[224, Sha3]
  sha3_256* = KeccakContext[256, Sha3]
  sha3_384* = KeccakContext[384, Sha3]
  sha3_512* = KeccakContext[512, Sha3]
  shake128* = KeccakContext[128, Shake]
  shake256* = KeccakContext[256, Shake]
  keccak* = keccak224 | keccak256 | keccak384 | keccak512 |
            sha3_224 | sha3_256 | sha3_384 | sha3_512

template THETA1(a, b, c: untyped) =
  (a)[(c)] = (b)[(c)] xor (b)[(c) + 5] xor (b)[(c) + 10] xor
             (b)[(c) + 15] xor (b)[(c) + 20]

template THETA2(a, b, c: untyped) =
  (a) = (b)[((c) + 4) mod 5] xor ROL(cast[uint64]((b)[((c) + 1) mod 5]), 1)

template THETA3(a, b) =
  (a)[(b)] = (a)[(b)] xor t
  (a)[(b) + 5] = (a)[(b) + 5] xor t
  (a)[(b) + 10] = (a)[(b) + 10] xor t
  (a)[(b) + 15] = (a)[(b) + 15] xor t
  (a)[(b) + 20] = (a)[(b) + 20] xor t

template RHOPI(a, b, c, d, e) =
  (a)[0] = (b)[(d)]
  (b)[(d)] = ROL(cast[uint64](c), e)
  (c) = (a)[0]

template CHI(a, b, c) =
  (a)[0] = (b)[(c)]
  (a)[1] = (b)[(c) + 1]
  (a)[2] = (b)[(c) + 2]
  (a)[3] = (b)[(c) + 3]
  (a)[4] = (b)[(c) + 4]
  (b)[(c)] = (b)[(c)] xor (not((a)[1]) and (a)[2])
  (b)[(c + 1)] = (b)[(c + 1)] xor (not((a)[2]) and (a)[3])
  (b)[(c + 2)] = (b)[(c + 2)] xor (not((a)[3]) and (a)[4])
  (b)[(c + 3)] = (b)[(c + 3)] xor (not((a)[4]) and (a)[0])
  (b)[(c + 4)] = (b)[(c + 4)] xor (not((a)[0]) and (a)[1])

template KECCAKROUND(a, b, c, r) =
  THETA1((b), (a), 0)
  THETA1((b), (a), 1)
  THETA1((b), (a), 2)
  THETA1((b), (a), 3)
  THETA1((b), (a), 4)

  THETA2((c), (b), 0)
  THETA3((a), 0)
  THETA2((c), (b), 1)
  THETA3((a), 1)
  THETA2((c), (b), 2)
  THETA3((a), 2)
  THETA2((c), (b), 3)
  THETA3((a), 3)
  THETA2((c), (b), 4)
  THETA3((a), 4)

  (c) = (a)[1]
  RHOPI((b), (a), (c), 10, 1)
  RHOPI((b), (a), (c), 7, 3)
  RHOPI((b), (a), (c), 11, 6)
  RHOPI((b), (a), (c), 17, 10)
  RHOPI((b), (a), (c), 18, 15)
  RHOPI((b), (a), (c), 3, 21)
  RHOPI((b), (a), (c), 5, 28)
  RHOPI((b), (a), (c), 16, 36)
  RHOPI((b), (a), (c), 8, 45)
  RHOPI((b), (a), (c), 21, 55)
  RHOPI((b), (a), (c), 24, 2)
  RHOPI((b), (a), (c), 4, 14)
  RHOPI((b), (a), (c), 15, 27)
  RHOPI((b), (a), (c), 23, 41)
  RHOPI((b), (a), (c), 19, 56)
  RHOPI((b), (a), (c), 13, 8)
  RHOPI((b), (a), (c), 12, 25)
  RHOPI((b), (a), (c), 2, 43)
  RHOPI((b), (a), (c), 20, 62)
  RHOPI((b), (a), (c), 14, 18)
  RHOPI((b), (a), (c), 22, 39)
  RHOPI((b), (a), (c), 9, 61)
  RHOPI((b), (a), (c), 6, 20)
  RHOPI((b), (a), (c), 1, 44)

  # Chi
  CHI((b), (a), 0)
  CHI((b), (a), 5)
  CHI((b), (a), 10)
  CHI((b), (a), 15)
  CHI((b), (a), 20)

  (a)[0] = (a)[0] xor RNDC[(r)]

proc keccakTransform(st: var array[25, uint64]) =
  var bc: array[5, uint64]
  var t: uint64

  st[0] = BSWAP(st[0])
  st[1] = BSWAP(st[1])
  st[2] = BSWAP(st[2])
  st[3] = BSWAP(st[3])
  st[4] = BSWAP(st[4])
  st[5] = BSWAP(st[5])
  st[6] = BSWAP(st[6])
  st[7] = BSWAP(st[7])
  st[8] = BSWAP(st[8])
  st[9] = BSWAP(st[9])
  st[10] = BSWAP(st[10])
  st[11] = BSWAP(st[11])
  st[12] = BSWAP(st[12])
  st[13] = BSWAP(st[13])
  st[14] = BSWAP(st[14])
  st[15] = BSWAP(st[15])
  st[16] = BSWAP(st[16])
  st[17] = BSWAP(st[17])
  st[18] = BSWAP(st[18])
  st[19] = BSWAP(st[19])
  st[20] = BSWAP(st[20])
  st[21] = BSWAP(st[21])
  st[22] = BSWAP(st[22])
  st[23] = BSWAP(st[23])
  st[24] = BSWAP(st[24])

  KECCAKROUND(st, bc, t, 0)
  KECCAKROUND(st, bc, t, 1)
  KECCAKROUND(st, bc, t, 2)
  KECCAKROUND(st, bc, t, 3)
  KECCAKROUND(st, bc, t, 4)
  KECCAKROUND(st, bc, t, 5)
  KECCAKROUND(st, bc, t, 6)
  KECCAKROUND(st, bc, t, 7)
  KECCAKROUND(st, bc, t, 8)
  KECCAKROUND(st, bc, t, 9)
  KECCAKROUND(st, bc, t, 10)
  KECCAKROUND(st, bc, t, 11)
  KECCAKROUND(st, bc, t, 12)
  KECCAKROUND(st, bc, t, 13)
  KECCAKROUND(st, bc, t, 14)
  KECCAKROUND(st, bc, t, 15)
  KECCAKROUND(st, bc, t, 16)
  KECCAKROUND(st, bc, t, 17)
  KECCAKROUND(st, bc, t, 18)
  KECCAKROUND(st, bc, t, 19)
  KECCAKROUND(st, bc, t, 20)
  KECCAKROUND(st, bc, t, 21)
  KECCAKROUND(st, bc, t, 22)
  KECCAKROUND(st, bc, t, 23)

  st[0] = BSWAP(st[0])
  st[1] = BSWAP(st[1])
  st[2] = BSWAP(st[2])
  st[3] = BSWAP(st[3])
  st[4] = BSWAP(st[4])
  st[5] = BSWAP(st[5])
  st[6] = BSWAP(st[6])
  st[7] = BSWAP(st[7])
  st[8] = BSWAP(st[8])
  st[9] = BSWAP(st[9])
  st[10] = BSWAP(st[10])
  st[11] = BSWAP(st[11])
  st[12] = BSWAP(st[12])
  st[13] = BSWAP(st[13])
  st[14] = BSWAP(st[14])
  st[15] = BSWAP(st[15])
  st[16] = BSWAP(st[16])
  st[17] = BSWAP(st[17])
  st[18] = BSWAP(st[18])
  st[19] = BSWAP(st[19])
  st[20] = BSWAP(st[20])
  st[21] = BSWAP(st[21])
  st[22] = BSWAP(st[22])
  st[23] = BSWAP(st[23])
  st[24] = BSWAP(st[24])

template sizeDigest*(ctx: KeccakContext): uint =
  (ctx.bits div 8)

template sizeBlock*(ctx: KeccakContext): uint =
  (200)

template rsize(ctx: KeccakContext): int =
  200 - 2 * (ctx.bits div 8)

template sizeDigest*(r: typedesc[keccak | shake128 | shake256]): int =
  when r is shake128:
    (16)
  elif r is keccak224 or r is sha3_224:
    (28)
  elif r is keccak256 or r is sha3_256 or r is shake256:
    (32)
  elif r is keccak384 or r is sha3_384:
    (48)
  elif r is keccak512 or r is sha3_512:
    (64)

template sizeBlock*(r: typedesc[keccak | shake128 | shake256]): int =
  (200)

proc init*(ctx: var KeccakContext) =
  ctx = type(ctx)()

proc clear*(ctx: var KeccakContext) {.inline.} =
  burnMem(ctx)

proc update*(ctx: var KeccakContext, data: ptr byte, ulen: uint) =
  var j = ctx.pt
  var s = cast[ptr UncheckedArray[byte]](data)
  var d = cast[ptr UncheckedArray[byte]](addr ctx.q[0])
  if ulen > 0'u:
    for i in 0..(ulen - 1):
      d[j] = d[j] xor s[i]
      inc(j)
      if j >= ctx.rsize:
        keccakTransform(ctx.q)
        j = 0
    ctx.pt = j

proc update*[T: bchar](ctx: var KeccakContext, data: openarray[T]) =
  if len(data) == 0:
    update(ctx, nil, 0'u)
  else:
    update(ctx, cast[ptr byte](unsafeAddr data[0]), cast[uint](len(data)))

proc finalizeKeccak(ctx: var KeccakContext) =
  var d = cast[ptr UncheckedArray[byte]](addr ctx.q[0])
  when ctx.kind == Sha3:
    d[ctx.pt] = d[ctx.pt] xor 0x06'u8
  else:
    d[ctx.pt] = d[ctx.pt] xor 0x01'u8
  d[ctx.rsize - 1] = d[ctx.rsize - 1] xor 0x80'u8
  keccakTransform(ctx.q)

proc xof*(ctx: var KeccakContext) =
  when ctx.kind != Shake:
    {.error: "Only `Shake128` and `Shake256` types are supported".}
  assert(ctx.kind == Shake)
  var d = cast[ptr UncheckedArray[byte]](addr ctx.q[0])
  d[ctx.pt] = d[ctx.pt] xor 0x1F'u8
  d[ctx.rsize - 1] = d[ctx.rsize - 1] xor 0x80'u8
  keccakTransform(ctx.q)
  ctx.pt = 0

proc output*(ctx: var KeccakContext, data: ptr byte, ulen: uint): uint =
  when ctx.kind != Shake:
    {.error: "Only `Shake128` and `Shake256` types are supported".}
  var j = ctx.pt
  var s = cast[ptr UncheckedArray[byte]](addr ctx.q[0])
  var d = cast[ptr UncheckedArray[byte]](data)

  if ulen > 0'u:
    for i in 0..(ulen - 1):
      if j >= ctx.rsize:
        keccakTransform(ctx.q)
        j = 0
      d[i] = s[j]
      inc(j)
    ctx.pt = j
    result = ulen

proc finish*(ctx: var KeccakContext, data: ptr byte, ulen: uint): uint =
  finalizeKeccak(ctx)
  var d = cast[ptr UncheckedArray[byte]](data)
  var s = cast[ptr UncheckedArray[byte]](addr ctx.q[0])
  if ulen >= ctx.sizeDigest:
    for i in 0..(ctx.sizeDigest - 1):
      d[i] = s[i]
    result = ctx.sizeDigest

proc finish*(ctx: var KeccakContext): MDigest[ctx.bits] =
  discard finish(ctx, cast[ptr byte](addr result.data[0]),
                 cast[uint](len(result.data)))

proc finish*[T: bchar](ctx: var KeccakContext, data: var openarray[T]) =
  assert(cast[uint](len(data)) >= ctx.sizeDigest)
  discard ctx.finish(cast[ptr byte](addr data[0]), cast[uint](len(data)))
