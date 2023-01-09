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
## Tests for BLAKE2-224/256/384/512 made according to
## [https://github.com/BLAKE2/BLAKE2/tree/master/testvectors].
import hash, utils
export hash

{.deadCodeElim: on.}

type
  Blake2bContext*[bits: static[int]] = object
    b: array[128, byte]
    h: array[8, uint64]
    t: array[2, uint64]
    c: int
    bb: array[128, byte]
    hb: array[8, uint64]
    tb: array[2, uint64]
    cb: int

  Blake2sContext*[bits: static[int]] = object
    b: array[64, byte]
    h: array[8, uint32]
    t: array[2, uint32]
    c: int
    bb: array[64, byte]
    hb: array[8, uint32]
    tb: array[2, uint32]
    cb: int

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
  [10'u8, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
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
  v[a] = v[a] + v[b] + x
  v[d] = ROR(v[d] xor v[a], 32)
  v[c] = v[c] + v[d]
  v[b] = ROR(v[b] xor v[c], 24)
  v[a] = v[a] + v[b] + y
  v[d] = ROR(v[d] xor v[a], 16)
  v[c] = v[c] + v[d]
  v[b] = ROR(v[b] xor v[c], 63)

template B2S_G(v, a, b, c, d, x, y: untyped) =
  v[a] = v[a] + v[b] + x
  v[d] = ROR(v[d] xor v[a], 16)
  v[c] = v[c] + v[d]
  v[b] = ROR(v[b] xor v[c], 12)
  v[a] = v[a] + v[b] + y
  v[d] = ROR(v[d] xor v[a], 8)
  v[c] = v[c] + v[d]
  v[b] = ROR(v[b] xor v[c], 7)

# This difference in implementation was made because Nim VM do not support more
# then 256 registers and so it is not enough for it to perform round in
# template.
when nimvm:
  proc B2BROUND(v: var array[16, uint64], m: array[16, uint64], n: int) =
    B2B_G(v, 0, 4,  8, 12, m[Sigma[n][ 0]], m[Sigma[n][ 1]])
    B2B_G(v, 1, 5,  9, 13, m[Sigma[n][ 2]], m[Sigma[n][ 3]])
    B2B_G(v, 2, 6, 10, 14, m[Sigma[n][ 4]], m[Sigma[n][ 5]])
    B2B_G(v, 3, 7, 11, 15, m[Sigma[n][ 6]], m[Sigma[n][ 7]])
    B2B_G(v, 0, 5, 10, 15, m[Sigma[n][ 8]], m[Sigma[n][ 9]])
    B2B_G(v, 1, 6, 11, 12, m[Sigma[n][10]], m[Sigma[n][11]])
    B2B_G(v, 2, 7,  8, 13, m[Sigma[n][12]], m[Sigma[n][13]])
    B2B_G(v, 3, 4,  9, 14, m[Sigma[n][14]], m[Sigma[n][15]])

  proc B2SROUND(v: var array[16, uint32], m: array[16, uint32], n: int) =
    B2S_G(v, 0, 4,  8, 12, m[Sigma[n][ 0]], m[Sigma[n][ 1]])
    B2S_G(v, 1, 5,  9, 13, m[Sigma[n][ 2]], m[Sigma[n][ 3]])
    B2S_G(v, 2, 6, 10, 14, m[Sigma[n][ 4]], m[Sigma[n][ 5]])
    B2S_G(v, 3, 7, 11, 15, m[Sigma[n][ 6]], m[Sigma[n][ 7]])
    B2S_G(v, 0, 5, 10, 15, m[Sigma[n][ 8]], m[Sigma[n][ 9]])
    B2S_G(v, 1, 6, 11, 12, m[Sigma[n][10]], m[Sigma[n][11]])
    B2S_G(v, 2, 7,  8, 13, m[Sigma[n][12]], m[Sigma[n][13]])
    B2S_G(v, 3, 4,  9, 14, m[Sigma[n][14]], m[Sigma[n][15]])
else:
  template B2BROUND(v, m, n: untyped) =
    B2B_G(v, 0, 4,  8, 12, m[Sigma[n][ 0]], m[Sigma[n][ 1]])
    B2B_G(v, 1, 5,  9, 13, m[Sigma[n][ 2]], m[Sigma[n][ 3]])
    B2B_G(v, 2, 6, 10, 14, m[Sigma[n][ 4]], m[Sigma[n][ 5]])
    B2B_G(v, 3, 7, 11, 15, m[Sigma[n][ 6]], m[Sigma[n][ 7]])
    B2B_G(v, 0, 5, 10, 15, m[Sigma[n][ 8]], m[Sigma[n][ 9]])
    B2B_G(v, 1, 6, 11, 12, m[Sigma[n][10]], m[Sigma[n][11]])
    B2B_G(v, 2, 7,  8, 13, m[Sigma[n][12]], m[Sigma[n][13]])
    B2B_G(v, 3, 4,  9, 14, m[Sigma[n][14]], m[Sigma[n][15]])

  template B2SROUND(v, m, n: untyped) =
    B2S_G(v, 0, 4,  8, 12, m[Sigma[n][ 0]], m[Sigma[n][ 1]])
    B2S_G(v, 1, 5,  9, 13, m[Sigma[n][ 2]], m[Sigma[n][ 3]])
    B2S_G(v, 2, 6, 10, 14, m[Sigma[n][ 4]], m[Sigma[n][ 5]])
    B2S_G(v, 3, 7, 11, 15, m[Sigma[n][ 6]], m[Sigma[n][ 7]])
    B2S_G(v, 0, 5, 10, 15, m[Sigma[n][ 8]], m[Sigma[n][ 9]])
    B2S_G(v, 1, 6, 11, 12, m[Sigma[n][10]], m[Sigma[n][11]])
    B2S_G(v, 2, 7,  8, 13, m[Sigma[n][12]], m[Sigma[n][13]])
    B2S_G(v, 3, 4,  9, 14, m[Sigma[n][14]], m[Sigma[n][15]])

proc blake2Transform(ctx: var Blake2bContext, last: bool) {.inline.} =
  var v {.noinit.}: array[16, uint64]
  var m {.noinit.}: array[16, uint64]

  when nimvm:
    for i in 0 ..< 8:
      v[i] = ctx.h[i]
      v[i + 8] = B2BIV[i]
  else:
    v[0] = ctx.h[0]; v[1] = ctx.h[1]
    v[2] = ctx.h[2]; v[3] = ctx.h[3]
    v[4] = ctx.h[4]; v[5] = ctx.h[5]
    v[6] = ctx.h[6]; v[7] = ctx.h[7]
    v[8] = B2BIV[0]; v[9] = B2BIV[1]
    v[10] = B2BIV[2]; v[11] = B2BIV[3]
    v[12] = B2BIV[4]; v[13] = B2BIV[5]
    v[14] = B2BIV[6]; v[15] = B2BIV[7]

  v[12] = v[12] xor ctx.t[0]
  v[13] = v[13] xor ctx.t[1]
  if last:
    v[14] = not(v[14])

  when nimvm:
    for i in 0 ..< 16:
      m[i] = leLoad64(ctx.b, i * 8)
  else:
    m[0] = leLoad64(ctx.b, 0); m[1] = leLoad64(ctx.b, 8)
    m[2] = leLoad64(ctx.b, 16); m[3] = leLoad64(ctx.b, 24)
    m[4] = leLoad64(ctx.b, 32); m[5] = leLoad64(ctx.b, 40)
    m[6] = leLoad64(ctx.b, 48); m[7] = leLoad64(ctx.b, 56)
    m[8] = leLoad64(ctx.b, 64); m[9] = leLoad64(ctx.b, 72)
    m[10] = leLoad64(ctx.b, 80); m[11] = leLoad64(ctx.b, 88)
    m[12] = leLoad64(ctx.b, 96); m[13] = leLoad64(ctx.b, 104)
    m[14] = leLoad64(ctx.b, 112); m[15] = leLoad64(ctx.b, 120)

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
  B2BROUND(v, m, 0)
  B2BROUND(v, m, 1)

  when nimvm:
    for i in 0 ..< 8:
      ctx.h[i] = ctx.h[i] xor (v[i] xor v[i + 8])
  else:
    ctx.h[0] = ctx.h[0] xor (v[0] xor v[0 + 8])
    ctx.h[1] = ctx.h[1] xor (v[1] xor v[1 + 8])
    ctx.h[2] = ctx.h[2] xor (v[2] xor v[2 + 8])
    ctx.h[3] = ctx.h[3] xor (v[3] xor v[3 + 8])
    ctx.h[4] = ctx.h[4] xor (v[4] xor v[4 + 8])
    ctx.h[5] = ctx.h[5] xor (v[5] xor v[5 + 8])
    ctx.h[6] = ctx.h[6] xor (v[6] xor v[6 + 8])
    ctx.h[7] = ctx.h[7] xor (v[7] xor v[7 + 8])

proc blake2Transform(ctx: var Blake2sContext, last: bool) {.inline.} =
  var v {.noinit.}: array[16, uint32]
  var m {.noinit.}: array[16, uint32]

  when nimvm:
    for i in 0 ..< 8:
      v[i] = ctx.h[i]
      v[i + 8] = B2SIV[i]
  else:
    v[0] = ctx.h[0]; v[1] = ctx.h[1]
    v[2] = ctx.h[2]; v[3] = ctx.h[3]
    v[4] = ctx.h[4]; v[5] = ctx.h[5]
    v[6] = ctx.h[6]; v[7] = ctx.h[7]
    v[8] = B2SIV[0]; v[9] = B2SIV[1]
    v[10] = B2SIV[2]; v[11] = B2SIV[3]
    v[12] = B2SIV[4]; v[13] = B2SIV[5]
    v[14] = B2SIV[6]; v[15] = B2SIV[7]

  v[12] = v[12] xor ctx.t[0]
  v[13] = v[13] xor ctx.t[1]
  if last:
    v[14] = not(v[14])

  when nimvm:
    for i in 0 ..< 16:
      m[i] = leLoad32(ctx.b, i * 4)
  else:
    m[0] = leLoad32(ctx.b, 0); m[1] = leLoad32(ctx.b, 4)
    m[2] = leLoad32(ctx.b, 8); m[3] = leLoad32(ctx.b, 12)
    m[4] = leLoad32(ctx.b, 16); m[5] = leLoad32(ctx.b, 20)
    m[6] = leLoad32(ctx.b, 24); m[7] = leLoad32(ctx.b, 28)
    m[8] = leLoad32(ctx.b, 32); m[9] = leLoad32(ctx.b, 36)
    m[10] = leLoad32(ctx.b, 40); m[11] = leLoad32(ctx.b, 44)
    m[12] = leLoad32(ctx.b, 48); m[13] = leLoad32(ctx.b, 52)
    m[14] = leLoad32(ctx.b, 56); m[15] = leLoad32(ctx.b, 60)

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

  when nimvm:
    for i in 0 ..< 8:
      ctx.h[i] = ctx.h[i] xor (v[i] xor v[i + 8])
  else:
    ctx.h[0] = ctx.h[0] xor (v[0] xor v[0 + 8])
    ctx.h[1] = ctx.h[1] xor (v[1] xor v[1 + 8])
    ctx.h[2] = ctx.h[2] xor (v[2] xor v[2 + 8])
    ctx.h[3] = ctx.h[3] xor (v[3] xor v[3 + 8])
    ctx.h[4] = ctx.h[4] xor (v[4] xor v[4 + 8])
    ctx.h[5] = ctx.h[5] xor (v[5] xor v[5 + 8])
    ctx.h[6] = ctx.h[6] xor (v[6] xor v[6 + 8])
    ctx.h[7] = ctx.h[7] xor (v[7] xor v[7 + 8])

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

proc init*[T: bchar](ctx: var Blake2Context, key: openArray[T]) {.inline.} =
  when ctx is Blake2sContext:
    when nimvm:
      for i in 0 ..< 64:
        ctx.b[i] = 0x00'u8
      for i in 0 ..< 8:
        ctx.h[i] = B2SIV[i]
    else:
      zeroMem(addr ctx.b[0], 64)
      ctx.h[0] = B2SIV[0]; ctx.h[1] = B2SIV[1]
      ctx.h[2] = B2SIV[2]; ctx.h[3] = B2SIV[3]
      ctx.h[4] = B2SIV[4]; ctx.h[5] = B2SIV[5]
      ctx.h[6] = B2SIV[6]; ctx.h[7] = B2SIV[7]

    ctx.t[0] = 0x00'u32
    ctx.t[1] = 0x00'u32
    let value = 0x01010000'u32 xor (uint32(len(key)) shl 8) xor
                uint32(ctx.sizeDigest)
  else:
    when nimvm:
      for i in 0 ..< 128:
        ctx.b[i] = 0x00'u8
      for i in 0 ..< 8:
        ctx.h[i] = B2BIV[i]
    else:
      zeroMem(addr ctx.b[0], 128)
      ctx.h[0] = B2BIV[0]; ctx.h[1] = B2BIV[1]
      ctx.h[2] = B2BIV[2]; ctx.h[3] = B2BIV[3]
      ctx.h[4] = B2BIV[4]; ctx.h[5] = B2BIV[5]
      ctx.h[6] = B2BIV[6]; ctx.h[7] = B2BIV[7]

    ctx.t[0] = 0x00'u64
    ctx.t[1] = 0x00'u64
    let value = 0x01010000'u64 xor (uint64(len(key)) shl 8) xor
                uint64(ctx.sizeDigest)

  ctx.h[0] = ctx.h[0] xor value
  ctx.c = 0

  if len(key) > 0:
    ctx.update(key)
    ctx.c = int(ctx.sizeBlock)

  copyMem(ctx.bb, 0, ctx.b, 0, len(ctx.b))
  copyMem(ctx.hb, 0, ctx.h, 0, len(ctx.h))
  ctx.tb[0] = ctx.t[0]
  ctx.tb[1] = ctx.t[1]
  ctx.cb = ctx.c

proc init*(ctx: var Blake2Context) {.inline.} =
  var zeroKey: array[0, byte]
  ctx.init(zeroKey)

proc init*(ctx: var Blake2Context, key: ptr byte, keylen: uint) {.inline.} =
  var zeroKey: array[0, byte]
  if not isNil(key) and keylen > 0'u:
    var ptrarr = cast[ptr UncheckedArray[byte]](key)
    ctx.init(ptrarr.toOpenArray(0, int(keylen) - 1))
  else:
    ctx.init(zeroKey)

proc clear*(ctx: var Blake2Context) {.inline.} =
  when nimvm:
    when ctx is Blake2sContext:
      for i in 0 ..< 64:
        ctx.b[i] = 0x00'u8
        ctx.bb[i] = 0x00'u8
      for i in 0 ..< 8:
        ctx.h[i] = 0x00'u32
        ctx.hb[i] = 0x00'u32
      ctx.t[0] = 0x00'u32
      ctx.t[1] = 0x00'u32
      ctx.tb[0] = 0x00'u32
      ctx.tb[1] = 0x00'u32
    elif ctx is Blake2bContext:
      for i in 0 ..< 128:
        ctx.b[i] = 0x00'u8
        ctx.bb[i] = 0x00'u8
      for i in 0 ..< 8:
        ctx.h[i] = 0x00'u64
        ctx.hb[i] = 0x00'u64
      ctx.t[0] = 0x00'u64
      ctx.t[1] = 0x00'u64
      ctx.tb[0] = 0x00'u64
      ctx.tb[1] = 0x00'u64
    ctx.c = 0
    ctx.cb = 0
  else:
    burnMem(ctx)

proc reset*(ctx: var Blake2Context) {.inline.} =
  copyMem(ctx.b, 0, ctx.bb, 0, len(ctx.b))
  copyMem(ctx.h, 0, ctx.hb, 0, len(ctx.h))
  ctx.t[0] = ctx.tb[0]
  ctx.t[1] = ctx.tb[1]
  ctx.c = ctx.cb

proc update*[T: bchar](ctx: var Blake2Context, data: openArray[T]) {.inline.} =
  var i = 0
  while i < len(data):
    if ctx.c == int(ctx.sizeBlock):
      when ctx is Blake2sContext:
        ctx.t[0] = ctx.t[0] + uint32(ctx.c)
        if ctx.t[0] < uint32(ctx.c):
          ctx.t[1] = ctx.t[1] + 1'u32
      else:
        ctx.t[0] = ctx.t[0] + uint64(ctx.c)
        if ctx.t[0] < uint64(ctx.c):
          ctx.t[1] = ctx.t[1] + 1'u64
      ctx.blake2Transform(false)
      ctx.c = 0
    when T is char:
      ctx.b[ctx.c] = byte(data[i])
    else:
      ctx.b[ctx.c] = data[i]
    inc(ctx.c)
    inc(i)

proc update*(ctx: var Blake2Context, pbytes: ptr byte,
             nbytes: uint) {.inline.} =
  var p = cast[ptr UncheckedArray[byte]](pbytes)
  ctx.update(toOpenArray(p, 0, int(nbytes) - 1))

proc finish*(ctx: var Blake2sContext,
             data: var openArray[byte]): uint {.inline, discardable.} =
  ctx.t[0] = ctx.t[0] + uint32(ctx.c)
  if ctx.t[0] < uint32(ctx.c):
    ctx.t[1] = ctx.t[1] + 1
  while ctx.c < int(ctx.sizeBlock):
    ctx.b[ctx.c] = 0x00'u8
    inc(ctx.c)
  ctx.blake2Transform(true)
  let length = min(int(ctx.sizeDigest), len(data))
  result = uint(length)
  for i in 0 ..< length:
    data[i] = byte((ctx.h[i shr 2] shr (8 * (i and 3))) and 0xFF'u32)

proc finish*(ctx: var Blake2bContext,
             data: var openArray[byte]): uint {.inline, discardable.} =
  ctx.t[0] = ctx.t[0] + uint64(ctx.c)
  if ctx.t[0] < uint64(ctx.c):
    ctx.t[1] = ctx.t[1] + 1'u64
  while ctx.c < int(ctx.sizeBlock):
    ctx.b[ctx.c] = 0x00'u8
    inc(ctx.c)
  ctx.blake2Transform(true)
  let length = min(int(ctx.sizeDigest), len(data))
  result = uint(length)
  for i in 0 ..< length:
    data[i] = byte((ctx.h[i shr 3] shr (8 * (i and 7))) and 0xFF'u64)

proc finish*(ctx: var Blake2sContext, pbytes: ptr byte,
             nbytes: uint): uint {.inline.} =
  var ptrarr = cast[ptr UncheckedArray[byte]](pbytes)
  result = ctx.finish(ptrarr.toOpenArray(0, int(nbytes) - 1))

proc finish*(ctx: var Blake2bContext, pbytes: ptr byte,
             nbytes: uint): uint {.inline.} =
  var ptrarr = cast[ptr UncheckedArray[byte]](pbytes)
  result = ctx.finish(ptrarr.toOpenArray(0, int(nbytes) - 1))

proc finish*(ctx: var Blake2sContext): MDigest[ctx.bits] =
  discard finish(ctx, result.data)

proc finish*(ctx: var Blake2bContext): MDigest[ctx.bits] =
  discard finish(ctx, result.data)
