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

proc THETA1(a: var array[5, uint64], b: array[25, uint64], c: int) {.inline.} =
  (a)[(c)] = (b)[(c)] xor (b)[(c) + 5] xor (b)[(c) + 10] xor
             (b)[(c) + 15] xor (b)[(c) + 20]

proc THETA2(a: var uint64, b: array[5, uint64], c: int) {.inline.} =
  (a) = (b)[((c) + 4) mod 5] xor ROL(cast[uint64]((b)[((c) + 1) mod 5]), 1)

proc THETA3(a: var array[25, uint64], b: int, t: uint64) =
  (a)[(b)] = (a)[(b)] xor t
  (a)[(b) + 5] = (a)[(b) + 5] xor t
  (a)[(b) + 10] = (a)[(b) + 10] xor t
  (a)[(b) + 15] = (a)[(b) + 15] xor t
  (a)[(b) + 20] = (a)[(b) + 20] xor t

proc RHOPI(a: var array[5, uint64], b: var array[25, uint64], c: var uint64, d, e: int) {.inline.} =
  (a)[0] = (b)[(d)]
  (b)[(d)] = ROL(cast[uint64](c), e)
  (c) = (a)[0]

proc CHI(a: var array[5, uint64], b: var array[25, uint64], c: int) {.inline.} =
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

proc KECCAKROUND(a: var array[25, uint64], b: var array[5, uint64], c: var uint64, r: int) {.inline.} =
  THETA1((b), (a), 0)
  THETA1((b), (a), 1)
  THETA1((b), (a), 2)
  THETA1((b), (a), 3)
  THETA1((b), (a), 4)

  THETA2((c), (b), 0)
  THETA3((a), 0, c)
  THETA2((c), (b), 1)
  THETA3((a), 1, c)
  THETA2((c), (b), 2)
  THETA3((a), 2, c)
  THETA2((c), (b), 3)
  THETA3((a), 3, c)
  THETA2((c), (b), 4)
  THETA3((a), 4, c)

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

proc stBSWAPAux(v: var uint64) {.used.} =
  v = BSWAP(v)

proc keccakTransform(st: var array[25, uint64]) =
  var bc: array[5, uint64]
  var t: uint64

  template stBSWAP(idx: int) =
    when nimvm:
      stBSWAPAux(st[idx])
    else:
      st[idx] = BSWAP(st[idx])

  stBSWAP(0)
  stBSWAP(1)
  stBSWAP(2)
  stBSWAP(3)
  stBSWAP(4)
  stBSWAP(5)
  stBSWAP(6)
  stBSWAP(7)
  stBSWAP(8)
  stBSWAP(9)
  stBSWAP(10)
  stBSWAP(11)
  stBSWAP(12)
  stBSWAP(13)
  stBSWAP(14)
  stBSWAP(15)
  stBSWAP(16)
  stBSWAP(17)
  stBSWAP(18)
  stBSWAP(19)
  stBSWAP(20)
  stBSWAP(21)
  stBSWAP(22)
  stBSWAP(23)
  stBSWAP(24)

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

  stBSWAP(0)
  stBSWAP(1)
  stBSWAP(2)
  stBSWAP(3)
  stBSWAP(4)
  stBSWAP(5)
  stBSWAP(6)
  stBSWAP(7)
  stBSWAP(8)
  stBSWAP(9)
  stBSWAP(10)
  stBSWAP(11)
  stBSWAP(12)
  stBSWAP(13)
  stBSWAP(14)
  stBSWAP(15)
  stBSWAP(16)
  stBSWAP(17)
  stBSWAP(18)
  stBSWAP(19)
  stBSWAP(20)
  stBSWAP(21)
  stBSWAP(22)
  stBSWAP(23)
  stBSWAP(24)

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

proc setQb(ctx: var KeccakContext, idx: int, v: byte) {.inline.} =
  when nimvm:
    let i = idx div sizeof(uint64)
    let bi = idx mod sizeof(uint64)
    let bt = bi * 8
    ctx.q[i] = (ctx.q[i] and (not (0xff'u64 shl bt))) or (v.uint64 shl bt)
  else:
    cast[ptr UncheckedArray[byte]](addr ctx.q[0])[idx] = v

proc getQb(ctx: KeccakContext, idx: int): byte {.inline.} =
  when nimvm:
    result = byte((ctx.q[idx div sizeof(uint64)] shr ((idx mod sizeof(uint64)) * 8)) and 0xff'u64)
  else:
    result = cast[ptr UncheckedArray[byte]](unsafeAddr ctx.q[0])[idx]
    assert(result == byte((ctx.q[idx div sizeof(uint64)] shr ((idx mod 8) * 8)) and 0x00000000000000ff'u64))

proc xorQb(ctx: var KeccakContext, idx: int, v: byte) {.inline.} =
  setQb(ctx, idx, getQb(ctx, idx) xor v)

proc init*(ctx: var KeccakContext) {.inline.} =
  ctx = type(ctx)()

proc clear*(ctx: var KeccakContext) {.inline.} =
  burnMem(ctx)

proc reset*(ctx: var KeccakContext) {.inline.} =
  init(ctx)

proc update*(ctx: var KeccakContext, data: openarray[byte]) =
  var j = ctx.pt
  if data.len > 0:
    for i in 0..(data.len - 1):
      ctx.xorQb(j, data[i])
      inc(j)
      if j >= ctx.rsize:
        keccakTransform(ctx.q)
        j = 0
    ctx.pt = j

proc update*(ctx: var KeccakContext, data: ptr byte, ulen: uint) {.inline.} =
  update(ctx, toOpenArray(cast[ptr array[0, byte]](data)[], 0, ulen.int - 1))

proc update*(ctx: var KeccakContext, data: openarray[char]) =
  if len(data) == 0:
    update(ctx, nil, 0'u)
  else:
    update(ctx, cast[ptr byte](unsafeAddr data[0]), cast[uint](len(data)))

proc finalizeKeccak(ctx: var KeccakContext) =
  when ctx.kind == Sha3:
    ctx.xorQb(ctx.pt, 0x06'u8)
  else:
    ctx.xorQb(ctx.pt, 0x01'u8)
  ctx.xorQb(ctx.rsize - 1, 0x80'u8)
  keccakTransform(ctx.q)

proc xof*(ctx: var KeccakContext) =
  when ctx.kind != Shake:
    {.error: "Only `Shake128` and `Shake256` types are supported".}
  assert(ctx.kind == Shake)
  var d = cast[ptr UncheckedArray[byte]](addr ctx.q[0])
  ctx.xorQb(ctx.pt, 0x1F'u8)
  ctx.xorQb(ctx.rsize - 1, 0x80'u8)
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

proc finishAux(ctx: var KeccakContext, data: var openarray[byte]): uint =
  finalizeKeccak(ctx)
  if data.len.uint >= ctx.sizeDigest:
    for i in 0..(ctx.sizeDigest.int - 1):
      data[i] = ctx.getQb(i)
    result = ctx.sizeDigest

proc finish*(ctx: var KeccakContext, data: var openarray[byte]) {.inline.} =
  discard finishAux(ctx, data)

proc finish*(ctx: var KeccakContext, data: ptr byte, ulen: uint): uint {.inline.} =
  finishAux(ctx, toOpenArray(cast[ptr array[0, byte]](data)[], 0, ulen.int - 1))

proc finish*(ctx: var KeccakContext): MDigest[ctx.bits] {.inline.} =
  finish(ctx, result.data)

proc finish*(ctx: var KeccakContext, data: var openarray[char]) {.inline.} =
  assert(cast[uint](len(data)) >= ctx.sizeDigest)
  ctx.finish(cast[ptr byte](addr data[0]), cast[uint](len(data)))
