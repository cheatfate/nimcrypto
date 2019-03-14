#
#
#                    NimCrypto
#        (c) Copyright 2018 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements BLAKE2 set of cryptographic hash functions designed
## by Jean-Philippe Aumasson, Luca Henzen, Willi Meier, Raphael C.W. Phan.
##
## This module supports BLAKE2s-224/256 and BLAKE2b-384/512.
##
## Tests for SHA3-225/256/384/512 made according to
## [https://github.com/BLAKE2/BLAKE2/tree/master/testvectors].

import hash, utils

{.deadCodeElim:on.}

type
  Blake2bContext[bits: static[int]] = object
    b: array[128, byte]
    h: array[8, uint64]
    t: array[2, uint64]
    c: int

  Blake2sContext[bits: static[int]] = object
    b: array[64, byte]
    h: array[8, uint32]
    t: array[2, uint32]
    c: int

  Blake2Context* = Blake2sContext | Blake2bContext

  blake2_224* = Blake2sContext[224]
  blake2_256* = Blake2sContext[256]
  blake2_384* = Blake2bContext[384]
  blake2_512* = Blake2bContext[512]

  blake2* = blake2_224 | blake2_256 | blake2_384 | blake2_512

const Sigma = [
  [0'u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14'u8, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11'u8, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7'u8, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9'u8, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2'u8, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12'u8, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13'u8, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6'u8, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10'u8, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0'u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14'u8, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
]

const B2BIV = [
  0x6A09E667F3BCC908'u64, 0xBB67AE8584CAA73B'u64,
  0x3C6EF372FE94F82B'u64, 0xA54FF53A5F1D36F1'u64,
  0x510E527FADE682D1'u64, 0x9B05688C2B3E6C1F'u64,
  0x1F83D9ABFB41BD6B'u64, 0x5BE0CD19137E2179'u64
]

const B2SIV = [
  0x6A09E667'u32, 0xBB67AE85'u32, 0x3C6EF372'u32, 0xA54FF53A'u32,
  0x510E527F'u32, 0x9B05688C'u32, 0x1F83D9AB'u32, 0x5BE0CD19'u32
]

template B2B_G(v, a, b, c, d, x, y: untyped) =
  (v)[(a)] = (v)[(a)] + (v)[(b)] + x
  (v)[(d)] = ROR((v)[(d)] xor (v)[(a)], 32)
  (v)[(c)] = (v)[(c)] + (v)[(d)]
  (v)[(b)] = ROR((v)[(b)] xor (v)[(c)], 24)
  (v)[(a)] = (v)[(a)] + (v)[(b)] + y
  (v)[(d)] = ROR((v)[(d)] xor (v)[(a)], 16)
  (v)[(c)] = (v)[(c)] + (v)[(d)]
  (v)[(b)] = ROR((v)[(b)] xor (v)[(c)], 63)

template B2S_G(v, a, b, c, d, x, y: untyped) =
  (v)[(a)] = (v)[(a)] + (v)[(b)] + x
  (v)[(d)] = ROR((v)[(d)] xor (v)[(a)], 16)
  (v)[(c)] = (v)[(c)] + (v)[(d)]
  (v)[(b)] = ROR((v)[(b)] xor (v)[(c)], 12)
  (v)[(a)] = (v)[(a)] + (v)[(b)] + y
  (v)[(d)] = ROR((v)[(d)] xor (v)[(a)], 8)
  (v)[(c)] = (v)[(c)] + (v)[(d)]
  (v)[(b)] = ROR((v)[(b)] xor (v)[(c)], 7)

template B2BROUND(v, m, n: untyped) =
  B2B_G(v, 0, 4,  8, 12, (m)[Sigma[(n)][ 0]], (m)[Sigma[(n)][ 1]])
  B2B_G(v, 1, 5,  9, 13, (m)[Sigma[(n)][ 2]], (m)[Sigma[(n)][ 3]])
  B2B_G(v, 2, 6, 10, 14, (m)[Sigma[(n)][ 4]], (m)[Sigma[(n)][ 5]])
  B2B_G(v, 3, 7, 11, 15, (m)[Sigma[(n)][ 6]], (m)[Sigma[(n)][ 7]])
  B2B_G(v, 0, 5, 10, 15, (m)[Sigma[(n)][ 8]], (m)[Sigma[(n)][ 9]])
  B2B_G(v, 1, 6, 11, 12, (m)[Sigma[(n)][10]], (m)[Sigma[(n)][11]])
  B2B_G(v, 2, 7,  8, 13, (m)[Sigma[(n)][12]], (m)[Sigma[(n)][13]])
  B2B_G(v, 3, 4, 9, 14,  (m)[Sigma[(n)][14]], (m)[Sigma[(n)][15]])

template B2SROUND(v, m, n: untyped) =
  B2S_G(v, 0, 4,  8, 12, (m)[Sigma[(n)][ 0]], (m)[Sigma[(n)][ 1]])
  B2S_G(v, 1, 5,  9, 13, (m)[Sigma[(n)][ 2]], (m)[Sigma[(n)][ 3]])
  B2S_G(v, 2, 6, 10, 14, (m)[Sigma[(n)][ 4]], (m)[Sigma[(n)][ 5]])
  B2S_G(v, 3, 7, 11, 15, (m)[Sigma[(n)][ 6]], (m)[Sigma[(n)][ 7]])
  B2S_G(v, 0, 5, 10, 15, (m)[Sigma[(n)][ 8]], (m)[Sigma[(n)][ 9]])
  B2S_G(v, 1, 6, 11, 12, (m)[Sigma[(n)][10]], (m)[Sigma[(n)][11]])
  B2S_G(v, 2, 7,  8, 13, (m)[Sigma[(n)][12]], (m)[Sigma[(n)][13]])
  B2S_G(v, 3, 4, 9, 14,  (m)[Sigma[(n)][14]], (m)[Sigma[(n)][15]])

template BLGETU64*(p, o): uint64 =
  (cast[uint64](cast[ptr byte](cast[uint](p) + o)[])) xor
    (cast[uint64](cast[ptr byte](cast[uint](p) + (o + 1))[]) shl 8) xor
    (cast[uint64](cast[ptr byte](cast[uint](p) + (o + 2))[]) shl 16) xor
    (cast[uint64](cast[ptr byte](cast[uint](p) + (o + 3))[]) shl 24) xor
    (cast[uint64](cast[ptr byte](cast[uint](p) + (o + 4))[]) shl 32) xor
    (cast[uint64](cast[ptr byte](cast[uint](p) + (o + 5))[]) shl 40) xor
    (cast[uint64](cast[ptr byte](cast[uint](p) + (o + 6))[]) shl 48) xor
    (cast[uint64](cast[ptr byte](cast[uint](p) + (o + 7))[]) shl 56)

template BLGETU32*(p, o): uint32 =
  (cast[uint32](cast[ptr byte](cast[uint](p) + o)[])) xor
    (cast[uint32](cast[ptr byte](cast[uint](p) + (o + 1))[]) shl 8) xor
    (cast[uint32](cast[ptr byte](cast[uint](p) + (o + 2))[]) shl 16) xor
    (cast[uint32](cast[ptr byte](cast[uint](p) + (o + 3))[]) shl 24)

template B2BFILL(m, c: untyped) =
  (m)[0] = BLGETU64(addr((c).b), 0); (m)[1] = BLGETU64(addr((c).b), 8)
  (m)[2] = BLGETU64(addr((c).b), 16); (m)[3] = BLGETU64(addr((c).b), 24)
  (m)[4] = BLGETU64(addr((c).b), 32); (m)[5] = BLGETU64(addr((c).b), 40)
  (m)[6] = BLGETU64(addr((c).b), 48); (m)[7] = BLGETU64(addr((c).b), 56)
  (m)[8] = BLGETU64(addr((c).b), 64); (m)[9] = BLGETU64(addr((c).b), 72)
  (m)[10] = BLGETU64(addr((c).b), 80); (m)[11] = BLGETU64(addr((c).b), 88)
  (m)[12] = BLGETU64(addr((c).b), 96); (m)[13] = BLGETU64(addr((c).b), 104)
  (m)[14] = BLGETU64(addr((c).b), 112); (m)[15] = BLGETU64(addr((c).b), 120)

template B2SFILL(m, c: untyped) =
  (m)[0] = BLGETU32(addr((c).b), 0); (m)[1] = BLGETU32(addr((c).b), 4)
  (m)[2] = BLGETU32(addr((c).b), 8); (m)[3] = BLGETU32(addr((c).b), 12)
  (m)[4] = BLGETU32(addr((c).b), 16); (m)[5] = BLGETU32(addr((c).b), 20)
  (m)[6] = BLGETU32(addr((c).b), 24); (m)[7] = BLGETU32(addr((c).b), 28)
  (m)[8] = BLGETU32(addr((c).b), 32); (m)[9] = BLGETU32(addr((c).b), 36)
  (m)[10] = BLGETU32(addr((c).b), 40); (m)[11] = BLGETU32(addr((c).b), 44)
  (m)[12] = BLGETU32(addr((c).b), 48); (m)[13] = BLGETU32(addr((c).b), 52)
  (m)[14] = BLGETU32(addr((c).b), 56); (m)[15] = BLGETU32(addr((c).b), 60)

template B2BINIT(v, c: untyped) =
  (v)[0] = (c).h[0]; (v)[1] = (c).h[1]
  (v)[2] = (c).h[2]; (v)[3] = (c).h[3]
  (v)[4] = (c).h[4]; (v)[5] = (c).h[5]
  (v)[6] = (c).h[6]; (v)[7] = (c).h[7]
  (v)[8] = B2BIV[0]; (v)[9] = B2BIV[1]
  (v)[10] = B2BIV[2]; (v)[11] = B2BIV[3]
  (v)[12] = B2BIV[4]; (v)[13] = B2BIV[5]
  (v)[14] = B2BIV[6]; (v)[15] = B2BIV[7]

template B2SINIT(v, c: untyped) =
  (v)[0] = (c).h[0]; (v)[1] = (c).h[1]
  (v)[2] = (c).h[2]; (v)[3] = (c).h[3]
  (v)[4] = (c).h[4]; (v)[5] = (c).h[5]
  (v)[6] = (c).h[6]; (v)[7] = (c).h[7]
  (v)[8] = B2SIV[0]; (v)[9] = B2SIV[1]
  (v)[10] = B2SIV[2]; (v)[11] = B2SIV[3]
  (v)[12] = B2SIV[4]; (v)[13] = B2SIV[5]
  (v)[14] = B2SIV[6]; (v)[15] = B2SIV[7]

template B2STORE(v, c, n: untyped) =
  (c).h[n] = (c).h[n] xor ((v)[(n)] xor (v)[(n) + 8])

proc blake2Transform(ctx: var Blake2bContext, last: bool) =
  var v: array[16, uint64]
  var m: array[16, uint64]

  B2BINIT(v, ctx)

  v[12] = v[12] xor ctx.t[0]
  v[13] = v[13] xor ctx.t[1]
  if last:
    v[14] = not(v[14])

  B2BFILL(m, ctx)

  B2BROUND(v, m, 0)
  B2BROUND(v, m, 1)
  B2BROUND(v, m, 2)
  B2BROUND(v, m, 3)
  B2BROUND(v, m, 4)
  B2BROUND(v, m, 5)
  B2BROUND(v, m, 6)
  B2BROUND(v, m, 7)
  B2BROUND(v, m, 8)
  B2BROUND(v, m, 9)
  B2BROUND(v, m, 10)
  B2BROUND(v, m, 11)

  B2STORE(v, ctx, 0)
  B2STORE(v, ctx, 1)
  B2STORE(v, ctx, 2)
  B2STORE(v, ctx, 3)
  B2STORE(v, ctx, 4)
  B2STORE(v, ctx, 5)
  B2STORE(v, ctx, 6)
  B2STORE(v, ctx, 7)

proc blake2Transform(ctx: var Blake2sContext, last: bool) =
  var v: array[16, uint32]
  var m: array[16, uint32]

  B2SINIT(v, ctx)

  v[12] = v[12] xor ctx.t[0]
  v[13] = v[13] xor ctx.t[1]
  if last:
    v[14] = not(v[14])

  B2SFILL(m, ctx)

  B2SROUND(v, m, 0)
  B2SROUND(v, m, 1)
  B2SROUND(v, m, 2)
  B2SROUND(v, m, 3)
  B2SROUND(v, m, 4)
  B2SROUND(v, m, 5)
  B2SROUND(v, m, 6)
  B2SROUND(v, m, 7)
  B2SROUND(v, m, 8)
  B2SROUND(v, m, 9)

  B2STORE(v, ctx, 0)
  B2STORE(v, ctx, 1)
  B2STORE(v, ctx, 2)
  B2STORE(v, ctx, 3)
  B2STORE(v, ctx, 4)
  B2STORE(v, ctx, 5)
  B2STORE(v, ctx, 6)
  B2STORE(v, ctx, 7)

template sizeDigest*(ctx: Blake2Context): uint =
  (ctx.bits div 8)

template sizeBlock*(ctx: Blake2Context): uint =
  when ctx is Blake2sContext:
    (64)
  else:
    (128)

template sizeDigest*(r: typedesc[blake2]): int =
  when r is blake2_224:
    (28)
  elif r is blake2_256:
    (32)
  elif r is blake2_384:
    (48)
  elif r is blake2_512:
    (64)

template sizeBlock*(r: typedesc[blake2]): int =
  when (r is blake2_224) or (r is blake2_256):
    (64)
  else:
    (128)

proc update*(ctx: var Blake2Context, data: ptr byte, ulen: uint) =
  var i = 0'u
  while i < ulen:
    if ctx.c == int(ctx.sizeBlock):
      when ctx is Blake2sContext:
        ctx.t[0] = ctx.t[0] + cast[uint32](ctx.c)
        if ctx.t[0] < cast[uint32](ctx.c):
          ctx.t[1] = ctx.t[1] + 1
      else:
        ctx.t[0] = ctx.t[0] + cast[uint64](ctx.c)
        if ctx.t[0] < cast[uint64](ctx.c):
          ctx.t[1] = ctx.t[1] + 1
      ctx.blake2Transform(false)
      ctx.c = 0
    var p = cast[ptr byte](cast[uint](data) + i)
    ctx.b[ctx.c] = p[]
    inc(ctx.c)
    inc(i)

proc update*[T: bchar](ctx: var Blake2Context, data: openarray[T]) {.inline.} =
  if len(data) == 0:
    ctx.update(nil, 0)
  else:
    ctx.update(cast[ptr byte](unsafeAddr data[0]), cast[uint](len(data)))

proc finish*(ctx: var Blake2sContext, data: ptr byte, ulen: uint): uint =
  ctx.t[0] = ctx.t[0] + cast[uint32](ctx.c)
  if ctx.t[0] < cast[uint32](ctx.c):
    ctx.t[1] = ctx.t[1] + 1
  while ctx.c < int(ctx.sizeBlock):
    ctx.b[ctx.c] = 0
    inc(ctx.c)
  ctx.blake2Transform(true)

  var length = int(ctx.sizeDigest)
  var p = cast[ptr UncheckedArray[byte]](data)
  if ulen >= ctx.sizeDigest:
    result = ctx.sizeDigest
    for i in 0..<length:
      p[i] = cast[byte]((ctx.h[i shr 2] shr (8 * (i and 3))) and 0xFF)

proc finish*(ctx: var Blake2bContext, data: ptr byte, ulen: uint): uint =
  ctx.t[0] = ctx.t[0] + cast[uint64](ctx.c)
  if ctx.t[0] < cast[uint64](ctx.c):
    ctx.t[1] = ctx.t[1] + 1

  while ctx.c < int(ctx.sizeBlock):
    ctx.b[ctx.c] = 0
    inc(ctx.c)
  ctx.blake2Transform(true)

  var length = int(ctx.sizeDigest)
  var p = cast[ptr UncheckedArray[byte]](data)
  if ulen >= ctx.sizeDigest:
    result = ctx.sizeDigest
    for i in 0..<length:
      p[i] = cast[byte]((ctx.h[i shr 3] shr (8 * (i and 7))) and 0xFF)

proc finish*(ctx: var Blake2sContext): MDigest[ctx.bits] =
  discard finish(ctx, cast[ptr byte](addr result.data[0]),
                 cast[uint](len(result.data)))

proc finish*(ctx: var Blake2bContext): MDigest[ctx.bits] =
  discard finish(ctx, cast[ptr byte](addr result.data[0]),
                 cast[uint](len(result.data)))

proc finish*[T: bchar](ctx: var Blake2Context, data: var openarray[T]) =
  doAssert(cast[uint](len(data)) >= ctx.sizeDigest)
  discard ctx.finish(cast[ptr byte](addr data[0]), cast[uint](len(data)))

proc init*(ctx: var Blake2Context, key: ptr byte = nil, keylen: uint = 0'u) =
  when ctx is Blake2sContext:
    zeroMem(addr ctx.b[0], sizeof(byte) * 64)
    ctx.h[0] = B2SIV[0]; ctx.h[1] = B2SIV[1]
    ctx.h[2] = B2SIV[2]; ctx.h[3] = B2SIV[3]
    ctx.h[4] = B2SIV[4]; ctx.h[5] = B2SIV[5]
    ctx.h[6] = B2SIV[6]; ctx.h[7] = B2SIV[7]
    let value = 0x01010000'u32 xor (cast[uint32](keylen) shl 8) xor
                cast[uint32](ctx.sizeDigest)
  else:
    zeroMem(addr ctx.b[0], sizeof(byte) * 128)
    ctx.h[0] = B2BIV[0]; ctx.h[1] = B2BIV[1]
    ctx.h[2] = B2BIV[2]; ctx.h[3] = B2BIV[3]
    ctx.h[4] = B2BIV[4]; ctx.h[5] = B2BIV[5]
    ctx.h[6] = B2BIV[6]; ctx.h[7] = B2BIV[7]
    let value = 0x01010000'u64 xor
                (cast[uint64](keylen) shl 8) xor ctx.sizeDigest

  ctx.h[0] = ctx.h[0] xor value
  ctx.t[0] = 0
  ctx.t[1] = 0
  ctx.c = 0

  if not isNil(key) and keylen > 0'u:
    ctx.update(key, keylen)
    ctx.c = int(ctx.sizeBlock)

proc init*[T: bchar](ctx: var Blake2Context, key: openarray[T]) {.inline.} =
  if len(key) == 0:
    ctx.init()
  else:
    ctx.init(cast[ptr byte](unsafeAddr key[0]), cast[uint](len(key)))

proc clear*(ctx: var Blake2Context) {.inline.} =
  burnMem(ctx)
