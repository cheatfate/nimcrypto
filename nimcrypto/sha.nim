#
#
#                    NimCrypto
#        (c) Copyright 2016 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements SHA1 (Secure Hash Algorithm 1) designed by
## National Security Agency.
import hash, utils
export hash

{.deadCodeElim:on.}

template SHA_MIX(t: int): uint32 =
  ROL(arr[(t + 13) and 15] xor arr[(t + 8) and 15] xor
      arr[(t + 2)  and 15] xor arr[t and 15], 1)

template SHA_ROUND1(o, t, fn, constant, A, B, C, D, E) =
  var tmp = beLoad32(blk, o + t * 4)
  arr[t and 15] = tmp
  E = E + tmp + ROL(A, 5) + fn + constant
  B = ROR(B, 2)

template SHA_ROUND2(t, fn, constant, A, B, C, D, E) =
  var tmp = SHA_MIX(t)
  arr[t and 15] = tmp
  E = E + tmp + ROL(A, 5) + fn + constant
  B = ROR(B, 2)

template T_0_15(o, t, A, B, C, D, E) =
  SHA_ROUND1(o, t, (((C xor D) and B) xor D), 0x5A827999'u32,
             A, B, C, D, E)

template T_16_19(t, A, B, C, D, E) =
  SHA_ROUND2(t, (((C xor D) and B) xor D), 0x5A827999'u32,
             A, B, C, D, E)

template T_20_39(t, A, B, C, D, E) =
  SHA_ROUND2(t, (B xor C xor D), 0x6ED9EBA1'u32, A, B, C, D, E)

template T_40_59(t, A, B, C, D, E) =
  SHA_ROUND2(t, ((B and C) + ((D and (B xor C)))), 0x8F1BBCDC'u32,
             A, B, C, D, E)

template T_60_79(t, A, B, C, D, E) =
  SHA_ROUND2(t, (B xor C xor D), 0xCA62C1D6'u32, A, B, C, D, E)


type
  Sha1Context*[bits: static[uint]] = object
    size: uint64
    h: array[5, uint32]
    w: array[64, byte]

  sha1* = Sha1Context[160]

template sizeDigest*(ctx: Sha1Context): uint =
  (160 div 8)

template sizeBlock*(ctx: Sha1Context): uint =
  (512 div 8)

template sizeDigest*(r: typedesc[sha1]): int =
  (160 div 8)

template sizeBlock*(r: typedesc[sha1]): int =
  (512 div 8)

proc init*(ctx: var Sha1Context) {.inline.} =
  ctx.size = 0'u64
  ctx.h[0] = 0x67452301'u32
  ctx.h[1] = 0xEFCDAB89'u32
  ctx.h[2] = 0x98BADCFE'u32
  ctx.h[3] = 0x10325476'u32
  ctx.h[4] = 0xC3D2E1F0'u32

proc sha1Transform[T: bchar](ctx: var Sha1Context,
                             blk: openArray[T],
                             offset: int) {.noinit, inline.} =
  var
    A, B, C, D, E: uint32
    arr {.noinit.}: array[16, uint32]

  A = ctx.h[0]
  B = ctx.h[1]
  C = ctx.h[2]
  D = ctx.h[3]
  E = ctx.h[4]

  T_0_15(offset, 0, A, B, C, D, E)
  T_0_15(offset, 1, E, A, B, C, D)
  T_0_15(offset, 2, D, E, A, B, C)
  T_0_15(offset, 3, C, D, E, A, B)
  T_0_15(offset, 4, B, C, D, E, A)
  T_0_15(offset, 5, A, B, C, D, E)
  T_0_15(offset, 6, E, A, B, C, D)
  T_0_15(offset, 7, D, E, A, B, C)
  T_0_15(offset, 8, C, D, E, A, B)
  T_0_15(offset, 9, B, C, D, E, A)
  T_0_15(offset, 10, A, B, C, D, E)
  T_0_15(offset, 11, E, A, B, C, D)
  T_0_15(offset, 12, D, E, A, B, C)
  T_0_15(offset, 13, C, D, E, A, B)
  T_0_15(offset, 14, B, C, D, E, A)
  T_0_15(offset, 15, A, B, C, D, E)

  T_16_19(16, E, A, B, C, D)
  T_16_19(17, D, E, A, B, C)
  T_16_19(18, C, D, E, A, B)
  T_16_19(19, B, C, D, E, A)

  T_20_39(20, A, B, C, D, E)
  T_20_39(21, E, A, B, C, D)
  T_20_39(22, D, E, A, B, C)
  T_20_39(23, C, D, E, A, B)
  T_20_39(24, B, C, D, E, A)
  T_20_39(25, A, B, C, D, E)
  T_20_39(26, E, A, B, C, D)
  T_20_39(27, D, E, A, B, C)
  T_20_39(28, C, D, E, A, B)
  T_20_39(29, B, C, D, E, A)
  T_20_39(30, A, B, C, D, E)
  T_20_39(31, E, A, B, C, D)
  T_20_39(32, D, E, A, B, C)
  T_20_39(33, C, D, E, A, B)
  T_20_39(34, B, C, D, E, A)
  T_20_39(35, A, B, C, D, E)
  T_20_39(36, E, A, B, C, D)
  T_20_39(37, D, E, A, B, C)
  T_20_39(38, C, D, E, A, B)
  T_20_39(39, B, C, D, E, A)

  T_40_59(40, A, B, C, D, E)
  T_40_59(41, E, A, B, C, D)
  T_40_59(42, D, E, A, B, C)
  T_40_59(43, C, D, E, A, B)
  T_40_59(44, B, C, D, E, A)
  T_40_59(45, A, B, C, D, E)
  T_40_59(46, E, A, B, C, D)
  T_40_59(47, D, E, A, B, C)
  T_40_59(48, C, D, E, A, B)
  T_40_59(49, B, C, D, E, A)
  T_40_59(50, A, B, C, D, E)
  T_40_59(51, E, A, B, C, D)
  T_40_59(52, D, E, A, B, C)
  T_40_59(53, C, D, E, A, B)
  T_40_59(54, B, C, D, E, A)
  T_40_59(55, A, B, C, D, E)
  T_40_59(56, E, A, B, C, D)
  T_40_59(57, D, E, A, B, C)
  T_40_59(58, C, D, E, A, B)
  T_40_59(59, B, C, D, E, A)

  T_60_79(60, A, B, C, D, E)
  T_60_79(61, E, A, B, C, D)
  T_60_79(62, D, E, A, B, C)
  T_60_79(63, C, D, E, A, B)
  T_60_79(64, B, C, D, E, A)
  T_60_79(65, A, B, C, D, E)
  T_60_79(66, E, A, B, C, D)
  T_60_79(67, D, E, A, B, C)
  T_60_79(68, C, D, E, A, B)
  T_60_79(69, B, C, D, E, A)
  T_60_79(70, A, B, C, D, E)
  T_60_79(71, E, A, B, C, D)
  T_60_79(72, D, E, A, B, C)
  T_60_79(73, C, D, E, A, B)
  T_60_79(74, B, C, D, E, A)
  T_60_79(75, A, B, C, D, E)
  T_60_79(76, E, A, B, C, D)
  T_60_79(77, D, E, A, B, C)
  T_60_79(78, C, D, E, A, B)
  T_60_79(79, B, C, D, E, A)

  ctx.h[0] += A
  ctx.h[1] += B
  ctx.h[2] += C
  ctx.h[3] += D
  ctx.h[4] += E

proc clear*(ctx: var Sha1Context) {.inline.} =
  when nimvm:
    for i in 0 ..< len(ctx.h):
      ctx.h[i] = 0x00'u32
      ctx.w[i] = 0x00'u8
    for i in len(ctx.h) ..< len(ctx.w):
      ctx.w[i] = 0x00'u8
    ctx.size = 0x00'u64
  else:
    burnMem(ctx)

proc reset*(ctx: var Sha1Context) {.inline.} =
  init(ctx)

proc update*[T: bchar](ctx: var Sha1Context, data: openArray[T]) {.inline.} =
  var length = len(data)
  if length > 0:
    var lenw = int(ctx.size and 63'u64) # ctx.size mod 64
    var offset = 0

    ctx.size = ctx.size + uint64(length)
    if lenw > 0:
      let left = min(64 - lenw, length)
      copyMem(ctx.w, lenw, data, offset, left)
      lenw = (lenw + left) and 63
      length = length - left
      offset = offset + left
      if lenw != 0:
        return
      sha1Transform(ctx, ctx.w, 0)

    while length >= 64:
      sha1Transform(ctx, data, offset)
      offset = offset + 64
      length = length - 64

    if length > 0:
      copyMem(ctx.w, 0, data, offset, length)

proc update*(ctx: var Sha1Context, pbytes: ptr byte,
             nbytes: uint) {.inline.} =
  var p = cast[ptr UncheckedArray[byte]](pbytes)
  ctx.update(toOpenArray(p, 0, int(nbytes) - 1))

proc finish*(ctx: var Sha1Context,
             data: var openArray[byte]): uint {.inline, discardable.} =
  let
    one80 = [0x80'u8]
    one00 = [0x00'u8]
  var
    pad {.noinit.}: array[8, byte]
  beStore64(pad, 0, uint64(ctx.size shl 3))
  update(ctx, one80)
  while (ctx.size and 63'u64) != (64 - 8):
    update(ctx, one00)
  update(ctx, pad)
  if len(data) >= int(ctx.sizeDigest):
    result = ctx.sizeDigest
    beStore32(data, 0, ctx.h[0])
    beStore32(data, 4, ctx.h[1])
    beStore32(data, 8, ctx.h[2])
    beStore32(data, 12, ctx.h[3])
    beStore32(data, 16, ctx.h[4])

proc finish*(ctx: var Sha1Context, pbytes: ptr byte,
             nbytes: uint): uint {.inline.} =
  var ptrarr = cast[ptr UncheckedArray[byte]](pbytes)
  result = ctx.finish(ptrarr.toOpenArray(0, int(nbytes) - 1))

proc finish*(ctx: var Sha1Context): MDigest[ctx.bits] =
  discard finish(ctx, result.data)
