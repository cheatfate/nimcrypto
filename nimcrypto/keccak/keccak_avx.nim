#
#
#                    NimCrypto
#         (c) Copyright 2026 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

{.push raises: [].}
{.used.}

import ".."/[hash, utils]
import "."/[keccak_common]
export hash

when defined(amd64):
  {.localPassc: "-msse2".}
  {.localPassc: "-mssse3".}

  when defined(vcc):
    {.pragma: x86type, bycopy, header:"<intrin.h>".}
    {.pragma: x86proc, nodecl, header:"<intrin.h>".}
  else:
    {.pragma: x86type, bycopy, header:"<x86intrin.h>".}
    {.pragma: x86proc, nodecl, header:"<x86intrin.h>".}

  const
    KECCAK_AVX_compress* = true

  type
    m128i* {.importc: "__m128i", x86type.} = object
      data: array[2, uint64]

  let RC {.align(32).}: array[48, uint64] = [
    0x0000000000000001'u64, 0x0'u64, 0x0000000000008082'u64, 0x0'u64,
    0x800000000000808A'u64, 0x0'u64, 0x8000000080008000'u64, 0x0'u64,
    0x000000000000808B'u64, 0x0'u64, 0x0000000080000001'u64, 0x0'u64,
    0x8000000080008081'u64, 0x0'u64, 0x8000000000008009'u64, 0x0'u64,
    0x000000000000008A'u64, 0x0'u64, 0x0000000000000088'u64, 0x0'u64,
    0x0000000080008009'u64, 0x0'u64, 0x000000008000000A'u64, 0x0'u64,
    0x000000008000808B'u64, 0x0'u64, 0x800000000000008B'u64, 0x0'u64,
    0x8000000000008089'u64, 0x0'u64, 0x8000000000008003'u64, 0x0'u64,
    0x8000000000008002'u64, 0x0'u64, 0x8000000000000080'u64, 0x0'u64,
    0x000000000000800A'u64, 0x0'u64, 0x800000008000000A'u64, 0x0'u64,
    0x8000000080008081'u64, 0x0'u64, 0x8000000000008080'u64, 0x0'u64,
    0x0000000080000001'u64, 0x0'u64, 0x8000000080008008'u64, 0x0'u64
  ]

  func mm_load_si128(mem_addr: ptr m128i): m128i {.
       importc: "_mm_load_si128", x86proc.}
  func mm_loadu_si128(mem_addr: ptr m128i): m128i {.
       importc: "_mm_loadu_si128", x86proc.}
  func mm_set_epi64x(e1, e0: uint64): m128i {.
       importc: "_mm_set_epi64x", x86proc.}
  func mm_set1_epi64x(a: uint64): m128i {.
       importc: "_mm_set1_epi64x", x86proc.}
  func mm_slli_epi64(a: m128i, imm8: uint32): m128i {.
       importc: "_mm_slli_epi64", x86proc.}
  func mm_srli_epi64(a: m128i, imm8: uint32): m128i {.
       importc: "_mm_srli_epi64", x86proc.}
  func mm_sllv_epi64(a: m128i, count: m128i): m128i {.
       importc: "_mm_sllv_epi64", x86proc.}
  func mm_srlv_epi64(a: m128i, count: m128i): m128i {.
       importc: "_mm_srlv_epi64", x86proc.}
  func mm_shuffle_epi8(a, b: m128i): m128i {.
       importc: "_mm_shuffle_epi8", x86proc.}
  func mm_or_si128(a, b: m128i): m128i {.
       importc: "_mm_or_si128", x86proc.}
  func mm_store_si128(mem_addr: ptr m128i, a: m128i) {.
       importc: "_mm_store_si128", x86proc.}
  func mm_storeu_si128(mem_addr: ptr m128i, a: m128i) {.
       importc: "_mm_storeu_si128", x86proc.}
  func mm_storel_epi64(mem_addr: ptr m128i, a: m128i) {.
       importc: "_mm_storel_epi64", x86proc.}
  func mm_storeh_pi(mem_addr: ptr m128i, a: m128i) {.
       importc: "_mm_storeh_pi", x86proc.}
  func mm_xor_si128(a, b: m128i): m128i {.
       importc: "_mm_xor_si128", x86proc.}
  func mm_setzero_si128(): m128i {.
       importc: "_mm_setzero_si128", x86proc.}
  func mm_add_epi64(a, b: m128i): m128i {.
       importc: "_mm_add_epi64", x86proc.}
  func mm_sub_epi64(a, b: m128i): m128i {.
       importc: "_mm_sub_epi64", x86proc.}
  func mm_ternarylogic_epi64(a, b, c: m128i, imm8: uint32): m128i {.
       importc: ")mm_ternarylogic_epi64", x86proc.}
  func mm_alignr_epi8(a, b: m128i, imm8: uint32): m128i {.
       importc: "_mm_alignr_epi8", x86proc.}
  func mm_blend_epi32(a, b: m128i, imm8: uint32): m128i {.
       importc: "mm_blend_epi32", x86proc.}
  func mm_move_epi64(a: m128i): m128i {.
       importc: "_mm_move_epi64", x86proc.}
  func mm_shuffle_epi32(a: m128i, imm8: uint32): m128i {.
       importc: "_mm_shuffle_epi32", x86proc.}
  func mm_unpacklo_epi64(a, b: m128i): m128i {.
       importc: "_mm_unpacklo_epi64", x86proc.}
  func mm_unpackhi_epi64(a, b: m128i): m128i {.
       importc: "_mm_unpackhi_epi64", x86proc.}


  let
    r2 {.align(32).} = mm_set_epi64x(44, 36)
    r4 {.align(32).} = mm_set_epi64x(20, 27)
    r6 {.align(32).} = mm_set_epi64x(25, 43)
    r5 {.align(32).} = mm_set_epi64x(10, 3)
    r8 {.align(32).} = mm_set_epi64x(21, 15)
    r3 {.align(32).} = mm_set_epi64x(55, 6)
    r11 {.align(32).} = mm_set_epi64x(56, 61)
    r0 {.align(32).} = mm_set_epi64x(1, 14)
    r10 {.align(32).} = mm_set_epi64x(2, 18)
    r9 {.align(32).} = mm_set_epi64x(8, 39)
    r1 {.align(32).} = mm_set_epi64x(28, 62)
    r7 {.align(32).} = mm_set_epi64x(45, 41)

template ROT(y, d: untyped): untyped =
  mm_xor_si128(mm_add_epi64(y, y), mm_srli_epi64(y, (63)))

template ROTV(x, d: untyped): untyped =
  mm_xor_si128(
    mm_sllv_epi64(x, d),
    mm_srlv_epi64(x, mm_sub_epi64(mm_set1_epi64x(0x40'u64), d)))

template load(t: typedesc[m128i], data: openArray[byte], index: int): m128i =
  mm_loadu_si128(cast[ptr m128i](unsafeAddr data[index]))

template loadAligned(
    t: typedesc[m128i],
    data: openArray[byte],
    index: int
): m128i =
  mm_load_si128(cast[ptr m128i](unsafeAddr data[index]))

template loadAligned(
    t: typedesc[m128i],
    data: openArray[uint64],
    index: int
): m128i =
  mm_load_si128(cast[ptr m128i](unsafeAddr data[index]))

template storeAligned(
    t: typedesc[m128i],
    a: m128i,
    data: var openArray[byte],
    index: int,
) =
  mm_store_si128(cast[ptr m128i](addr data[index]), a)

template loadData(data, rsiz, x0, x1, x2, x3, x4, x5, x6, y: untyped): untyped =
  x0 = m128i.load(data, 0)
  x1 = m128i.load(data, 1)
  y[0] = mm_xor_si128(x0, y[0])
  y[1] = mm_xor_si128(x1, y[1])
  x2 = m128i.load(data, 2)
  x3 = m128i.load(data, 3)
  x4 = m128i.load(data, 4)
  x0 = mm_alignr_epi8(x3, x2, 8)
  x1 = mm_alignr_epi8(x4, x3, 8)
  x3 = mm_blend_epi32(x2, x4, 0xC)
  y[2] = mm_xor_si128(x0, y[2])
  y[3] = mm_xor_si128(x1, y[3])
  if rsiz == 72:
    x3 = mm_move_epi64(x3)
  y[4] = mm_xor_si128(x3, y[4])
  if rsiz == 104:
    x4 = m128i.load(data, 5)
    x2 = m128i.load(data, 6)
    y[5] = mm_xor_si128(x4, y[5])
    x2 = mm_move_epi64(x2)
    y[6] = mm_xor_si128(x2, y[6])
  elif rsiz == 136:
    x4 = m128i.load(data, 7)
    x2 = m128i.load(data, 8)
    x2 = mm_alignr_epi8(x2, x4, 8)
    x4 = mm_move_epi64(x4)

    x0 = m128i.load(data, 5)
    x1 = m128i.load(data, 6)
    y[7] = mm_xor_si128(x2, y[7])
    y[9] = mm_xor_si128(x4, y[9])
    y[5] = mm_xor_si128(x0, y[5])
    y[6] = mm_xor_si128(x1, y[6])
  elif rsiz == 144:
    x4 = m128i.load(data, 7)
    x2 = m128i.load(data, 8)
    x1 = m128i.load(data, 9)
    x0 = mm_alignr_epi8(x1, x2, 8)
    x0 = mm_move_epi64(x0)

    y[8] = mm_xor_si128(x0, y[8])
    x2 = mm_alignr_epi8(x2, x4, 8)
    x4 = mm_move_epi64(x4)

    x0 = m128i.load(data, 5)
    x1 = m128i.load(data, 6)
    y[7] = mm_xor_si128(x2, y[7])
    y[9] = mm_xor_si128(x4, y[9])
    y[5] = mm_xor_si128(x0, y[5])
    y[6] = mm_xor_si128(x1, y[6])

template keccakTransform(
    rounds: untyped, y: untyped,
    x0, x1, x2, x3, x4, x5, x6: untyped,
    r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11: untyped
) =
  for q in countup(0, rounds, 2):
    x2 = mm_xor_si128(y[4], y[9])
    x0 = mm_ternarylogic_epi64(y[0], y[7], y[5], 0x96)
    x0 = mm_ternarylogic_epi64(y[10], y[2], x0, 0x96)

    x1 = mm_ternarylogic_epi64(y[1], y[3], y[6], 0x96)
    x1 = mm_ternarylogic_epi64(y[11], y[8], x1, 0x96)

    x3 = mm_shuffle_epi32(x2, 0x4e)
    x2 = mm_ternarylogic_epi64(x3, x2, y[12], 0x96)

    x4 = mm_alignr_epi8(x0, x2, 8)
    x3 = mm_xor_si128(x0, ROT(x1, 1))
    x0 = mm_xor_si128(x2, ROT(x0, 1))
    x2 = mm_xor_si128(x1, ROT(x4, 1))

    x0 = mm_alignr_epi8(x3, x0, 8)
    x1 = mm_alignr_epi8(x2, x3, 8)
    y[2] = mm_xor_si128(y[2], x0)
    x2 = mm_shuffle_epi32(x2, 0xEE)

    {.noSideEffect.}:
      y[2] = ROTV(y[2], r2)
    y[4] = mm_xor_si128(y[4], x2)
    y[0] = mm_xor_si128(y[0], x0)
    y[1] = mm_xor_si128(y[1], x1)

    {.noSideEffect.}:
      y[4]  = ROTV(y[4], r4)
    y[12] = mm_xor_si128(y[12], x2)
    y[6]  = mm_xor_si128(y[6], x1)
    y[5]  = mm_xor_si128(y[5], x0)

    {.noSideEffect.}:
      y[6]  = ROTV(y[6], r6)
    y[9]  = mm_xor_si128(y[9], x2)
    y[3]  = mm_xor_si128(y[3], x1)
    y[11] = mm_xor_si128(y[11], x1)

    {.noSideEffect.}:
      y[5] = ROTV(y[5], r5)
    y[7] = mm_xor_si128(y[7], x0)
    y[8] = mm_xor_si128(y[8], x1)

    x2 = mm_alignr_epi8(y[6], y[5], 8)
    {.noSideEffect.}:
      y[8] = ROTV(y[8], r8)
      y[3] = ROTV(y[3], r3)

    x4 = mm_blend_epi32(y[0], y[12], 0x3)
    y[10] = mm_xor_si128(y[10], x0)
    {.noSideEffect.}:
      y[11] = ROTV(y[11], r11)

    x5 = mm_unpacklo_epi64(y[4], y[0])
    y[4] = mm_unpackhi_epi64(y[3], y[4])
    {.noSideEffect.}:
      x0 = ROTV(x4, r0)

    x3 = mm_ternarylogic_epi64(x5, y[2], x2, 0xD2)
    {.noSideEffect.}:
      y[10] = ROTV(y[10], r10)
    x1 = mm_alignr_epi8(x0, y[11], 8)

    {.noSideEffect.}:
      y[9] = ROTV(y[9], r9)
    x4 = mm_ternarylogic_epi64(y[2], x2, y[8], 0xD2)
    x2 = mm_ternarylogic_epi64(x2, y[8], x1, 0xD2)

    y[5] = mm_unpacklo_epi64(y[9], y[5])
    y[8] = mm_ternarylogic_epi64(y[8], x1, x5, 0xD2)
    x1 = mm_ternarylogic_epi64(x1, x5, y[2], 0xD2)

    {.noSideEffect.}:
      y[1] = ROTV(y[1], r1)
    y[11] = mm_alignr_epi8(y[11], y[10], 8)

    y[0] = mm_ternarylogic_epi64(y[1], y[4], y[5], 0xD2)
    {.noSideEffect.}:
      y[7] = ROTV(y[7], r7)
    y[3] = mm_blend_epi32(y[3], y[6], 0xC)
    y[6] = mm_unpackhi_epi64(y[6], y[9])

    y[2] = mm_ternarylogic_epi64(y[4], y[5], y[7], 0xD2)
    y[4] = mm_ternarylogic_epi64(y[11], y[1], y[4], 0xD2)
    y[9] = mm_ternarylogic_epi64(y[5], y[7], y[11], 0xD2)
    y[7] = mm_ternarylogic_epi64(y[7], y[11], y[1], 0xD2)

    x5 = mm_alignr_epi8(y[3], x0, 8)
    x0 = mm_blend_epi32(x0, y[10], 0x3)
    y[10] = mm_alignr_epi8(y[10], y[6], 8)

    y[1] = mm_unpackhi_epi64(x2, y[8])
    y[11] = mm_unpacklo_epi64(y[9], y[7])
    y[8] = mm_unpacklo_epi64(x2, y[8])

    x2 = mm_ternarylogic_epi64(y[10], x0, x5, 0xD2)
    y[5] = mm_ternarylogic_epi64(x5, y[3], y[6], 0xD2)
    y[6] = mm_ternarylogic_epi64(y[6], x2, x0, 0xD2)

    y[3] = mm_unpackhi_epi64(y[9], y[7])
    y[9] = mm_alignr_epi8(x1, x2, 8)

    y[10] = mm_unpacklo_epi64(y[0], y[2])
    y[7] = mm_unpacklo_epi64(x3, x4)

    y[12] = mm_shuffle_epi32(y[4], 0x44)
    y[4] = mm_unpackhi_epi64(x1, y[4])
    y[2] = mm_unpackhi_epi64(y[0], y[2])
    y[0] = mm_unpackhi_epi64(x3, x4)
    {.noSideEffect.}:
      x0 = m128i.loadAligned(RC, q)
    y[0] = mm_xor_si128(y[0], x0)

    x2 = mm_xor_si128(y[4],y[9])
    x0 = mm_ternarylogic_epi64(y[0], y[7], y[5], 0x96)
    x0 = mm_ternarylogic_epi64(y[10], y[2], x0, 0x96)

    x1 = mm_ternarylogic_epi64(y[1], y[3], y[6], 0x96)
    x1 = mm_ternarylogic_epi64(y[11], y[8], x1, 0x96)

    x3 = mm_shuffle_epi32(x2, 0x4E)
    x2 = mm_ternarylogic_epi64(x3, x2, y[12], 0x96)

    x4 = mm_alignr_epi8(x0, x2, 8)
    x3 = mm_xor_si128(x0, ROT(x1, 1))
    x0 = mm_xor_si128(x2, ROT(x0, 1))
    x2 = mm_xor_si128(x1, ROT(x4, 1))

    x0 = mm_alignr_epi8(x3, x0, 8)
    x1 = mm_alignr_epi8(x2, x3, 8)
    y[2] = mm_xor_si128(y[2], x0)
    x2 = mm_shuffle_epi32(x2, 0xEE)

    {.noSideEffect.}:
      y[2] = ROTV(y[2], r2)
    y[4] = mm_xor_si128(y[4], x2)
    y[0] = mm_xor_si128(y[0], x0)
    y[1] = mm_xor_si128(y[1], x1)

    {.noSideEffect.}:
      y[4] = ROTV(y[4], r4)
    y[12] = mm_xor_si128(y[12], x2)
    y[6] = mm_xor_si128(y[6], x1)
    y[5] = mm_xor_si128(y[5], x0)

    {.noSideEffect.}:
      y[6] = ROTV(y[6], r6)
    y[9] = mm_xor_si128(y[9], x2)
    y[3] = mm_xor_si128(y[3], x1)
    y[11] = mm_xor_si128(y[11], x1)

    {.noSideEffect.}:
      y[5] = ROTV(y[5], r5)
    y[7] = mm_xor_si128(y[7], x0)
    y[8] = mm_xor_si128(y[8], x1)

    x2 = mm_alignr_epi8(y[6], y[5], 8)
    {.noSideEffect.}:
      y[8] = ROTV(y[8], r8)
      y[3] = ROTV(y[3], r3)

    x4 = mm_blend_epi32(y[0], y[12], 0x3)
    y[10] = mm_xor_si128(y[10], x0)
    {.noSideEffect.}:
      y[11] = ROTV(y[11], r11)

    x5 = mm_unpacklo_epi64(y[4], y[0])
    y[4] = mm_unpackhi_epi64(y[3], y[4])
    {.noSideEffect.}:
      x0 = ROTV(x4, r0)

    x3 = mm_ternarylogic_epi64(x5, y[2], x2, 0xD2)
    {.noSideEffect.}:
      y[10] = ROTV(y[10], r10)
    x1 = mm_alignr_epi8(x0, y[11], 8)

    {.noSideEffect.}:
      y[9] = ROTV(y[9], r9)
    x4 = mm_ternarylogic_epi64(y[2], x2, y[8], 0xD2)
    x2 = mm_ternarylogic_epi64(x2, y[8], x1, 0xD2)

    y[5] = mm_unpacklo_epi64(y[9], y[5])
    y[8] = mm_ternarylogic_epi64(y[8], x1, x5, 0xD2)
    x1 = mm_ternarylogic_epi64(x1, x5, y[2], 0xD2)

    {.noSideEffect.}:
      y[1] = ROTV(y[1], r1)
    y[11] = mm_alignr_epi8(y[11], y[10], 8)

    y[0] = mm_ternarylogic_epi64(y[1], y[4], y[5], 0xD2)
    {.noSideEffect.}:
      y[7] = ROTV(y[7], r7)
    y[3] = mm_blend_epi32(y[3], y[6], 0xC)
    y[6] = mm_unpackhi_epi64(y[6], y[9])

    y[2] = mm_ternarylogic_epi64(y[4], y[5], y[7], 0xD2)
    y[4] = mm_ternarylogic_epi64(y[11], y[1], y[4], 0xD2)
    y[9] = mm_ternarylogic_epi64(y[5], y[7], y[11], 0xD2)
    y[7] = mm_ternarylogic_epi64(y[7], y[11], y[1], 0xD2)

    x5 = mm_alignr_epi8(y[3], x0, 8)
    x0 = mm_blend_epi32(x0, y[10], 0x3)
    y[10] = mm_alignr_epi8(y[10], y[6], 8)

    y[1] = mm_unpackhi_epi64(x2, y[8])
    y[11] = mm_unpacklo_epi64(y[9], y[7])
    y[8] = mm_unpacklo_epi64(x2, y[8])

    x2 = mm_ternarylogic_epi64(y[10], x0, x5, 0xD2)
    y[5] = mm_ternarylogic_epi64(x5, y[3], y[6], 0xD2)
    y[6] = mm_ternarylogic_epi64(y[6], x2, x0, 0xD2)

    y[3] = mm_unpackhi_epi64(y[9], y[7])
    y[9] = mm_alignr_epi8(x1, x2, 8)

    y[10] = mm_unpacklo_epi64(y[0], y[2])
    y[7] = mm_unpacklo_epi64(x3, x4)

    y[12] = mm_shuffle_epi32(y[4], 0x44)
    y[4] = mm_unpackhi_epi64(x1, y[4])
    y[2] = mm_unpackhi_epi64(y[0], y[2])
    y[0] = mm_unpackhi_epi64(x3, x4)
    {.noSideEffect.}:
      x0 = m128i.loadAligned(RC, q + 1)
    y[0] = mm_xor_si128(y[0], x0)

func keccakCompress*(
    state: var openArray[byte],
    data: openArray[byte],
    rsize: int,
) =

  var y {.align(32), noinit.}: array[13, m128i]
  var x0, x1, x2, x3, x4, x5, x6 {.align(32), noinit.}: m128i
  var temp {.align(32).}: array[144, byte]

  y[0] = m128i.loadAligned(state, 0); y[1] = m128i.loadAligned(state, 1)
  y[2] = m128i.loadAligned(state, 2); y[3] = m128i.loadAligned(state, 3)
  y[4] = m128i.loadAligned(state, 4); y[5] = m128i.loadAligned(state, 5)
  y[6] = m128i.loadAligned(state, 6); y[7] = m128i.loadAligned(state, 7)
  y[8] = m128i.loadAligned(state, 8); y[9] = m128i.loadAligned(state, 9)
  y[10] = m128i.loadAligned(state, 10); y[11] = m128i.loadAligned(state, 11)
  y[12] = m128i.loadAligned(state, 12)

  var offset = 0
  let
    blocksCount = len(data) div rsize
    bytesLeft = len(data) mod rsize
  for i in 0 ..< blocksCount:
    loadData(
      data.toOpenArray(offset, offset + rsize - 1), rsize,
      x0, x1, x2, x3, x4, x5, x6, y)
    keccakTransform(24, y, x0, x1, x2, x3, x4, x5, x6,
      r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11)
    offset += rsize

  copyMem(temp, 0, data, offset, bytesLeft)


  m128i.storeAligned(y[0], state, 0); m128i.storeAligned(y[1], state, 1)
  m128i.storeAligned(y[2], state, 2); m128i.storeAligned(y[3], state, 3)
  m128i.storeAligned(y[4], state, 4); m128i.storeAligned(y[5], state, 5)
  m128i.storeAligned(y[6], state, 6); m128i.storeAligned(y[7], state, 7)
  m128i.storeAligned(y[8], state, 8); m128i.storeAligned(y[9], state, 9)
  m128i.storeAligned(y[10], state, 10); m128i.storeAligned(y[11], state, 11)
  m128i.storeAligned(y[12], state, 12)
