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

{.deadCodeElim:on.}

template SHA_ROT(x, m, r: uint32): uint32 =
  ((x shl m) or (x shr r))

template SHA_ROL(x, n: uint32): uint32 =
  SHA_ROT(x, n, 32 - n)

template SHA_ROR(x, n: uint32): uint32 =
  SHA_ROT(x, 32 - n, n)

template SHA_SRC(t: int): uint32 =
  GETU32(blk, t * 4)

template SHA_MIX(t: int): uint32 =
  SHA_ROL(arr[(t + 13) and 15] xor arr[(t + 8) and 15] xor
          arr[(t + 2)  and 15] xor arr[t and 15], 1)

template SHA_ROUND1(t, fn, constant, A, B, C, D, E) =
  var tmp = GETU32(blk, t * 4)
  arr[t and 15] = tmp
  E = E + tmp + SHA_ROL(A, 5) + fn + constant
  B = SHA_ROR(B, 2)

template SHA_ROUND2(t, fn, constant, A, B, C, D, E) =
  var tmp = SHA_MIX(t)
  arr[t and 15] = tmp
  E = E + tmp + SHA_ROL(A, 5) + fn + constant
  B = SHA_ROR(B, 2)

template T_0_15(t, A, B, C, D, E) =
  SHA_ROUND1(t, (((C xor D) and B) xor D), 0x5A827999'u32,
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
    w: array[16, uint32]

  sha1* = Sha1Context[160]

template sizeDigest*(ctx: Sha1Context): uint =
  (160 div 8)

template sizeBlock*(ctx: Sha1Context): uint =
  (512 div 8)

template sizeDigest*(r: typedesc[sha1]): int =
  (160 div 8)

template sizeBlock*(r: typedesc[sha1]): int =
  (512 div 8)

proc init*(ctx: var Sha1Context) =
  ctx.size = 0'u64
  ctx.h[0] = 0x67452301'u32
  ctx.h[1] = 0xEFCDAB89'u32
  ctx.h[2] = 0x98BADCFE'u32
  ctx.h[3] = 0x10325476'u32
  ctx.h[4] = 0xC3D2E1F0'u32

proc sha1Transform(ctx: var Sha1Context, blk: ptr byte) {.noinit.} =
  var
    A, B, C, D, E: uint32
    arr: array[16, uint32]

  A = ctx.h[0]
  B = ctx.h[1]
  C = ctx.h[2]
  D = ctx.h[3]
  E = ctx.h[4]

  T_0_15(0, A, B, C, D, E)
  T_0_15(1, E, A, B, C, D)
  T_0_15(2, D, E, A, B, C)
  T_0_15(3, C, D, E, A, B)
  T_0_15(4, B, C, D, E, A)
  T_0_15(5, A, B, C, D, E)
  T_0_15(6, E, A, B, C, D)
  T_0_15(7, D, E, A, B, C)
  T_0_15(8, C, D, E, A, B)
  T_0_15(9, B, C, D, E, A)
  T_0_15(10, A, B, C, D, E)
  T_0_15(11, E, A, B, C, D)
  T_0_15(12, D, E, A, B, C)
  T_0_15(13, C, D, E, A, B)
  T_0_15(14, B, C, D, E, A)
  T_0_15(15, A, B, C, D, E)

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
  burnMem(ctx)

proc update*(ctx: var Sha1Context, pBytes: ptr byte, nBytes: uint) =
  var lenw = ctx.size and 63
  var length = cast[uint64](nBytes)
  var slider = pBytes
  ctx.size += length

  if lenw > 0'u64:
    var left = 64'u64 - lenw
    if length < left:
      left = length
    copyMem(cast[ptr byte](cast[uint64](addr ctx.w[0]) + lenw), slider, left)
    lenw = (lenw + left) and 63
    length = length - left
    slider = cast[ptr byte](cast[uint64](slider) + left)
    if lenw != 0:
      return
    sha1Transform(ctx, cast[ptr byte](addr ctx.w[0]))

  while length >= 64'u64:
    sha1Transform(ctx, slider)
    slider = cast[ptr byte](cast[uint64](slider) + 64)
    length = length - 64

  if length > 0'u64:
    copyMem(addr ctx.w[0], slider, length)

proc update*[T: bchar](ctx: var Sha1Context, data: openarray[T]) =
  if len(data) == 0:
    ctx.update(nil, 0)
  else:
    ctx.update(cast[ptr byte](unsafeAddr data[0]), cast[uint](len(data)))

proc finish*(ctx: var Sha1Context, pBytes: ptr byte,
             nBytes: uint): uint =
  result = 0
  var pad: array[64, byte]
  var padlen: array[2, uint32]
  pad[0] = 0x80'u8
  let s0 = ctx.size shr 39
  let s1 = ctx.size shl 3
  EPUTU32(addr padlen[0], 0, s0)
  EPUTU32(addr padlen[0], 4, s1)
  var i = cast[int](ctx.size and 63'u64)
  update(ctx, addr pad[0], cast[uint](1 + (63 and (55 - i))))
  update(ctx, cast[ptr byte](addr padlen[0]), 8'u)
  if nBytes >= ctx.sizeDigest:
    result = ctx.sizeDigest
    PUTU32(pBytes, 0, ctx.h[0])
    PUTU32(pBytes, 4, ctx.h[1])
    PUTU32(pBytes, 8, ctx.h[2])
    PUTU32(pBytes, 12, ctx.h[3])
    PUTU32(pBytes, 16, ctx.h[4])

proc finish*(ctx: var Sha1Context): MDigest[160] =
  discard finish(ctx, cast[ptr byte](addr result.data[0]),
                 cast[uint](len(result.data)))

proc finish*[T: bchar](ctx: var Sha1Context, data: var openarray[T]) =
  assert(cast[uint](len(data)) >= ctx.sizeDigest)
  discard ctx.finish(cast[ptr byte](addr data[0]), cast[uint](len(data)))
