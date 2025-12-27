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
    SHA3_AVX_compress* = true

  type
    m128i* {.importc: "__m128i", x86type.} = object
      data: array[2, uint64]

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

template ROL64in128(a, o: untyped): untyped =
  mm_or_si128(mm_slli_epi64(a, o), mm_srli_epi64(a, 64-(o)))

template ROL64in128_8(a: untyped): untyped =
  let rho8 {.align(32).} =
    m128i(data: [0x0605040302010007'u64, 0x0E0D0C0B0A09080F'u64])
  mm_shuffle_epi8(a, _mm_load_si128(unsafeAddr rho8))

template ROL64in128_56(a: untyped): untyped =
  let rho56 {.align(32).} =
    m128i(data: [0x0007060504030201'u64, 0x080F0E0D0C0B0A09'u64])
  mm_shuffle_epi8(a, _mm_load_si128(rho56))



  func mm_unpacklo_epi64(a, b: m128i): m128i {.
       importc: "_mm_unpacklo_epi64", x86proc.}
  func mm_unpackhi_epi64(a, b: m128i): m128i {.
       importc: "_mm_unpackhi_epi64", x86proc.}
  func mm_setzero_si128(): m128i {.
       importc: "_mm_setzero_si128", x86proc.}
  func mm_xor_si128(a, b: m128i): m128i {.
       importc: "_mm_xor_si128", x86proc.}
  func mm_andnot_si128(a, b: m128i): m128i {.
       importc: "_mm_andnot_si128", x86proc.}
  func mm_shuffle_epi32(a: m128i, imm8: uint32): m128i {.
       importc: "_mm_shuffle_epi32", x86proc.}

  func mm_add_epi32(a, b: m128i): m128i {.
       importc: "_mm_add_epi32", x86proc.}
  func mm_add_epi64(a, b: m128i): m128i {.
       importc: "_mm_add_epi64", x86proc.}
  func mm_slli_epi32(a: m128i, imm8: uint32): m128i {.
       importc: "_mm_slli_epi32", x86proc.}

  func mm_srli_epi32(a: m128i, imm8: uint32): m128i {.
       importc: "_mm_srli_epi32", x86proc.}

  func mm_alignr_epi8(a, b: m128i, imm8: uint32): m128i {.
       importc: "_mm_alignr_epi8", x86proc.}
  func mm_xor_si128(a, b: m128i): m128i {.
       importc: "_mm_xor_si128", x86proc.}

  template ROT(x: m128i, y: uint32): m128i =
    mm_or_si128(mm_slli_epi64(x, y), mm_srli_epi64(x, 64'u32 - y))
  template ROT1(x): m128i =
    mm_or_si128(mm_add_epi64(x, x), mm_srli_epi64(x, 63'u32))
