#
#
#                    NimCrypto
#        (c) Copyright 2024 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module is optimized SHA2-256 (Secure Hash Algorithm 2) implementation
## for AMD64 using CPU SHA extension.
##
## This implementation is Nim version of C code by Nir Drucker and Shay Gueron
## (AWS Cryptographic Algorithms Group. (ndrucker@amazon.com,
## gueron@amazon.com)).
## https://github.com/aws-samples/sha2-with-c-intrinsic/blob/master/src/sha256_compress_x86_64_sha_ext.c

{.push raises: [].}
{.used.}

when defined(amd64):
  import "."/sha2_common

  {.passC:"-msha".}
  {.passC:"-msse2".}

  when defined(vcc):
    {.pragma: x86type, bycopy, header:"<intrin.h>".}
    {.pragma: x86proc, nodecl, header:"<intrin.h>".}
  else:
    {.pragma: x86type, bycopy, header:"<x86intrin.h>".}
    {.pragma: x86proc, nodecl, header:"<x86intrin.h>".}

  const
    SHA2_SHAEXT_sha256Compress* = true

  type
    m128i* {.importc: "__m128i", x86type.} = object
      data: array[2, uint64]
    mmask8* {.importc: "__mmask8", x86type.} = uint8

  func mm_sha256rnds2_epu32(a, b, k: m128i): m128i {.
       importc: "_mm_sha256rnds2_epu32", x86proc.}
  func mm_sha256msg1_epu32(a, b: m128i): m128i {.
       importc: "_mm_sha256msg1_epu32", x86proc.}
  func mm_sha256msg2_epu32(a, b: m128i): m128i {.
       importc: "_mm_sha256msg2_epu32", x86proc.}
  func mm_setr_epi32(e3, e2, e1, e0: uint32): m128i {.
       importc: "_mm_setr_epi32", x86proc.}
  func mm_set_epi64x(e1, e0: uint64): m128i {.
       importc: "_mm_set_epi64x", x86proc.}
  func mm_shuffle_epi32(a: m128i, imm8: uint32): m128i {.
       importc: "_mm_shuffle_epi32", x86proc.}
  func mm_shuffle_epi8(a, b: m128i): m128i {.
       importc: "_mm_shuffle_epi8", x86proc.}
  func mm_loadu_si128(mem_addr: ptr m128i): m128i {.
       importc: "_mm_loadu_si128", x86proc.}
  func mm_store_si128(mem_addr: ptr m128i, a: m128i) {.
       importc: "_mm_store_si128", x86proc.}
  func mm_alignr_epi8(a, b: m128i, imm8: uint32): m128i {.
       importc: "_mm_alignr_epi8", x86proc.}
  func mm_blend_epi16(a, b: m128i, imm8: uint32): m128i {.
       importc: "_mm_blend_epi16", x86proc.}
  func mm_add_epi32(a, b: m128i): m128i {.
       importc: "_mm_add_epi32", x86proc.}

  template load(t: typedesc[m128i], data: openArray[byte], index: int): m128i =
    mm_loadu_si128(cast[ptr m128i](unsafeAddr data[index]))

  template load(t: typedesc[m128i], data: openArray[uint32],
                index: int): m128i =
    mm_loadu_si128(cast[ptr m128i](unsafeAddr data[index]))

  template store(t: typedesc[m128i], data: var openArray[uint32], index: int,
                 value: m128i) =
    mm_store_si128(cast[ptr m128i](unsafeAddr data[index]), value)

  template setconst(i: static[int]): untyped =
    mm_setr_epi32(K0[i * 4], K0[i * 4 + 1], K0[i * 4 + 2], K0[i * 4 + 3])

  proc sha256Compress*(state: var array[8, uint32],
                       data: openArray[byte],
                       blocks: int) {.noinit, inline.} =
    let shufMask =
      mm_set_epi64x(0x0c0d0e0f08090a0b'u64, 0x0405060700010203'u64)

    var
      msgtmp: array[4, m128i]
      msg: m128i
      tmp = mm_shuffle_epi32(m128i.load(state, 0), 0xB1'u32)
      state1 = mm_shuffle_epi32(m128i.load(state, 4), 0x1B'u32)
      state0 = mm_alignr_epi8(tmp, state1, 8)
      blocksCount = blocks
      offset = 0

    state1 = mm_blend_epi16(state1, tmp, 0xF0'u32)

    while blocksCount > 0:
      var
        state0_save = state0
        state1_save = state1

      msgtmp[0] = mm_shuffle_epi8(m128i.load(data, offset), shufMask)
      msg = mm_add_epi32(msgtmp[0], setconst(0))
      state1 = mm_sha256rnds2_epu32(state1, state0, msg)
      msg = mm_shuffle_epi32(msg, 0x0E'u32)
      state0 = mm_sha256rnds2_epu32(state0, state1, msg)

      msgtmp[1] = mm_shuffle_epi8(m128i.load(data, offset + 16), shufMask)
      msg = mm_add_epi32(msgtmp[1], setconst(1))
      state1 = mm_sha256rnds2_epu32(state1, state0, msg)
      msg = mm_shuffle_epi32(msg, 0x0E'u32)
      state0 = mm_sha256rnds2_epu32(state0, state1, msg)
      msgtmp[0] = mm_sha256msg1_epu32(msgtmp[0], msgtmp[1])

      msgtmp[2] = mm_shuffle_epi8(m128i.load(data, offset + 32), shufMask)
      msg = mm_add_epi32(msgtmp[2], setconst(2))
      state1 = mm_sha256rnds2_epu32(state1, state0, msg)
      msg = mm_shuffle_epi32(msg, 0x0E'u32)
      state0 = mm_sha256rnds2_epu32(state0, state1, msg)
      msgtmp[1] = mm_sha256msg1_epu32(msgtmp[1], msgtmp[2])

      msgtmp[3] = mm_shuffle_epi8(m128i.load(data, offset + 48), shufMask)

      # i = 3 (3)
      msg = mm_add_epi32(msgtmp[3], setconst(3))
      state1 = mm_sha256rnds2_epu32(state1, state0, msg)
      tmp = mm_alignr_epi8(msgtmp[3], msgtmp[2], 4)
      msgtmp[0] = mm_add_epi32(msgtmp[0], tmp)
      msgtmp[0] = mm_sha256msg2_epu32(msgtmp[0], msgtmp[3])
      msg = mm_shuffle_epi32(msg, 0x0E'u32)
      state0 = mm_sha256rnds2_epu32(state0, state1, msg)
      msgtmp[2] = mm_sha256msg1_epu32(msgtmp[2], msgtmp[3])
      # i = 4 (0)
      msg = mm_add_epi32(msgtmp[0], setconst(4))
      state1 = mm_sha256rnds2_epu32(state1, state0, msg)
      tmp = mm_alignr_epi8(msgtmp[0], msgtmp[3], 4)
      msgtmp[1] = mm_add_epi32(msgtmp[1], tmp)
      msgtmp[1] = mm_sha256msg2_epu32(msgtmp[1], msgtmp[0])
      msg = mm_shuffle_epi32(msg, 0x0E'u32)
      state0 = mm_sha256rnds2_epu32(state0, state1, msg)
      msgtmp[3] = mm_sha256msg1_epu32(msgtmp[3], msgtmp[0])
      # i = 5 (1)
      msg = mm_add_epi32(msgtmp[1], setconst(5))
      state1 = mm_sha256rnds2_epu32(state1, state0, msg)
      tmp = mm_alignr_epi8(msgtmp[1], msgtmp[0], 4)
      msgtmp[2] = mm_add_epi32(msgtmp[2], tmp)
      msgtmp[2] = mm_sha256msg2_epu32(msgtmp[2], msgtmp[1])
      msg = mm_shuffle_epi32(msg, 0x0E'u32)
      state0 = mm_sha256rnds2_epu32(state0, state1, msg)
      msgtmp[0] = mm_sha256msg1_epu32(msgtmp[0], msgtmp[1])
      # i = 6 (2)
      msg = mm_add_epi32(msgtmp[2], setconst(6))
      state1 = mm_sha256rnds2_epu32(state1, state0, msg)
      tmp = mm_alignr_epi8(msgtmp[2], msgtmp[1], 4)
      msgtmp[3] = mm_add_epi32(msgtmp[3], tmp)
      msgtmp[3] = mm_sha256msg2_epu32(msgtmp[3], msgtmp[2])
      msg = mm_shuffle_epi32(msg, 0x0E'u32)
      state0 = mm_sha256rnds2_epu32(state0, state1, msg)
      msgtmp[1] = mm_sha256msg1_epu32(msgtmp[1], msgtmp[2])
      # i = 7 (3)
      msg = mm_add_epi32(msgtmp[3], setconst(7))
      state1 = mm_sha256rnds2_epu32(state1, state0, msg)
      tmp = mm_alignr_epi8(msgtmp[3], msgtmp[2], 4)
      msgtmp[0] = mm_add_epi32(msgtmp[0], tmp)
      msgtmp[0] = mm_sha256msg2_epu32(msgtmp[0], msgtmp[3])
      msg = mm_shuffle_epi32(msg, 0x0E'u32)
      state0 = mm_sha256rnds2_epu32(state0, state1, msg)
      msgtmp[2] = mm_sha256msg1_epu32(msgtmp[2], msgtmp[3])
      # i = 8 (0)
      msg = mm_add_epi32(msgtmp[0], setconst(8))
      state1 = mm_sha256rnds2_epu32(state1, state0, msg)
      tmp = mm_alignr_epi8(msgtmp[0], msgtmp[3], 4)
      msgtmp[1] = mm_add_epi32(msgtmp[1], tmp)
      msgtmp[1] = mm_sha256msg2_epu32(msgtmp[1], msgtmp[0])
      msg = mm_shuffle_epi32(msg, 0x0E'u32)
      state0 = mm_sha256rnds2_epu32(state0, state1, msg)
      msgtmp[3] = mm_sha256msg1_epu32(msgtmp[3], msgtmp[0])
      # i = 9 (1)
      msg = mm_add_epi32(msgtmp[1], setconst(9))
      state1 = mm_sha256rnds2_epu32(state1, state0, msg)
      tmp = mm_alignr_epi8(msgtmp[1], msgtmp[0], 4)
      msgtmp[2] = mm_add_epi32(msgtmp[2], tmp)
      msgtmp[2] = mm_sha256msg2_epu32(msgtmp[2], msgtmp[1])
      msg = mm_shuffle_epi32(msg, 0x0E'u32)
      state0 = mm_sha256rnds2_epu32(state0, state1, msg)
      msgtmp[0] = mm_sha256msg1_epu32(msgtmp[0], msgtmp[1])
      # i = 10 (2)
      msg = mm_add_epi32(msgtmp[2], setconst(10))
      state1 = mm_sha256rnds2_epu32(state1, state0, msg)
      tmp = mm_alignr_epi8(msgtmp[2], msgtmp[1], 4)
      msgtmp[3] = mm_add_epi32(msgtmp[3], tmp)
      msgtmp[3] = mm_sha256msg2_epu32(msgtmp[3], msgtmp[2])
      msg = mm_shuffle_epi32(msg, 0x0E'u32)
      state0 = mm_sha256rnds2_epu32(state0, state1, msg)
      msgtmp[1] = mm_sha256msg1_epu32(msgtmp[1], msgtmp[2])
      # i = 11 (3)
      msg = mm_add_epi32(msgtmp[3], setconst(11))
      state1 = mm_sha256rnds2_epu32(state1, state0, msg)
      tmp = mm_alignr_epi8(msgtmp[3], msgtmp[2], 4)
      msgtmp[0] = mm_add_epi32(msgtmp[0], tmp)
      msgtmp[0] = mm_sha256msg2_epu32(msgtmp[0], msgtmp[3])
      msg = mm_shuffle_epi32(msg, 0x0E'u32)
      state0 = mm_sha256rnds2_epu32(state0, state1, msg)
      msgtmp[2] = mm_sha256msg1_epu32(msgtmp[2], msgtmp[3])
      # i = 12 (0)
      msg = mm_add_epi32(msgtmp[0], setconst(12))
      state1 = mm_sha256rnds2_epu32(state1, state0, msg)
      tmp = mm_alignr_epi8(msgtmp[0], msgtmp[3], 4)
      msgtmp[1] = mm_add_epi32(msgtmp[1], tmp)
      msgtmp[1] = mm_sha256msg2_epu32(msgtmp[1], msgtmp[0])
      msg = mm_shuffle_epi32(msg, 0x0E'u32)
      state0 = mm_sha256rnds2_epu32(state0, state1, msg)
      msgtmp[3] = mm_sha256msg1_epu32(msgtmp[3], msgtmp[0])
      # i = 13 (1)
      msg = mm_add_epi32(msgtmp[1], setconst(13))
      state1 = mm_sha256rnds2_epu32(state1, state0, msg)
      tmp = mm_alignr_epi8(msgtmp[1], msgtmp[0], 4)
      msgtmp[2] = mm_add_epi32(msgtmp[2], tmp)
      msgtmp[2] = mm_sha256msg2_epu32(msgtmp[2], msgtmp[1])
      msg = mm_shuffle_epi32(msg, 0x0E'u32)
      state0 = mm_sha256rnds2_epu32(state0, state1, msg)
      msgtmp[0] = mm_sha256msg1_epu32(msgtmp[0], msgtmp[1])
      # i = 14 (2)
      msg = mm_add_epi32(msgtmp[2], setconst(14))
      state1 = mm_sha256rnds2_epu32(state1, state0, msg)
      tmp = mm_alignr_epi8(msgtmp[2], msgtmp[1], 4)
      msgtmp[3] = mm_add_epi32(msgtmp[3], tmp)
      msgtmp[3] = mm_sha256msg2_epu32(msgtmp[3], msgtmp[2])
      msg = mm_shuffle_epi32(msg, 0x0E'u32)
      state0 = mm_sha256rnds2_epu32(state0, state1, msg)
      msgtmp[1] = mm_sha256msg1_epu32(msgtmp[1], msgtmp[2])

      msg = mm_add_epi32(msgtmp[3], setconst(15))
      state1 = mm_sha256rnds2_epu32(state1, state0, msg)
      msg = mm_shuffle_epi32(msg, 0x0E'u32)
      state0 = mm_sha256rnds2_epu32(state0, state1, msg)

      state0 = mm_add_epi32(state0, state0_save)
      state1 = mm_add_epi32(state1, state1_save)

      offset += sha256.sizeBlock()
      dec(blocksCount)

    tmp = mm_shuffle_epi32(state0, 0x1B'u32)
    state1 = mm_shuffle_epi32(state1, 0xB1'u32)
    state0 = mm_blend_epi16(tmp, state1, 0xF0'u32)
    state1 = mm_alignr_epi8(state1, tmp, 8)

    m128i.store(state, 0, state0)
    m128i.store(state, 4, state1)
