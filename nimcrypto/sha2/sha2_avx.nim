#
#
#                    NimCrypto
#        (c) Copyright 2024 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module is optimized SHA2-256 (Secure Hash Algorithm 2) implementation
## for AMD64 using CPU AVX extension.
##
## This implementation is Nim version of C code by Nir Drucker and Shay Gueron
## (AWS Cryptographic Algorithms Group. (ndrucker@amazon.com,
## gueron@amazon.com)).
## https://github.com/aws-samples/sha2-with-c-intrinsic/blob/master/src/sha256_compress_x86_64_avx.c
##
## Which is based on Gueron, S., Krasnov, V.
## Parallelizing message schedules to accelerate the computations of hash
## functions. J Cryptogr Eng 2, 241–253 (2012).
## https://doi.org/10.1007/s13389-012-0037-z

{.push raises: [].}

import "."/sha2_common

when defined(amd64):
  {.passC:"-msse2".}

  when defined(vcc):
    {.pragma: x86type, bycopy, header:"<intrin.h>".}
    {.pragma: x86proc, nodecl, header:"<intrin.h>".}
  else:
    {.pragma: x86type, bycopy, header:"<x86intrin.h>".}
    {.pragma: x86proc, nodecl, header:"<x86intrin.h>".}

  const
    SHA2_AVX_sha256Compress* = true
    SHA2_AVX_sha512Compress* = true

  type
    m128i* {.importc: "__m128i", x86type.} = object
      data: array[2, uint64]

  let
    K0D = K0
    K1D = K1

  func mm_setr_epi32(e3, e2, e1, e0: uint32): m128i {.
       importc: "_mm_setr_epi32", x86proc.}
  func mm_loadu_si128(mem_addr: ptr m128i): m128i {.
       importc: "_mm_loadu_si128", x86proc.}
  func mm_store_si128(mem_addr: ptr m128i, a: m128i) {.
       importc: "_mm_store_si128", x86proc.}
  func mm_shuffle_epi32(a: m128i, imm8: uint32): m128i {.
       importc: "_mm_shuffle_epi32", x86proc.}
  func mm_shuffle_epi8(a, b: m128i): m128i {.
       importc: "_mm_shuffle_epi8", x86proc.}
  func mm_add_epi32(a, b: m128i): m128i {.
       importc: "_mm_add_epi32", x86proc.}
  func mm_add_epi64(a, b: m128i): m128i {.
       importc: "_mm_add_epi64", x86proc.}
  func mm_slli_epi32(a: m128i, imm8: uint32): m128i {.
       importc: "_mm_slli_epi32", x86proc.}
  func mm_slli_epi64(a: m128i, imm8: uint32): m128i {.
       importc: "_mm_slli_epi64", x86proc.}
  func mm_srli_epi32(a: m128i, imm8: uint32): m128i {.
       importc: "_mm_srli_epi32", x86proc.}
  func mm_srli_epi64(a: m128i, imm8: uint32): m128i {.
       importc: "_mm_srli_epi64", x86proc.}
  func mm_alignr_epi8(a, b: m128i, imm8: uint32): m128i {.
       importc: "_mm_alignr_epi8", x86proc.}
  func mm_xor_si128(a, b: m128i): m128i {.
       importc: "_mm_xor_si128", x86proc.}

  template load(t: typedesc[m128i], data: openArray[byte], index: int): m128i =
    mm_loadu_si128(cast[ptr m128i](unsafeAddr data[index]))

  template load(t: typedesc[m128i], data: openArray[uint32],
                index: int): m128i =
    mm_loadu_si128(cast[ptr m128i](unsafeAddr data[index]))

  template load(t: typedesc[m128i], data: openArray[uint64],
                index: int): m128i =
    mm_loadu_si128(cast[ptr m128i](unsafeAddr data[index]))

  template store(t: typedesc[m128i], data: var openArray[uint32], index: int,
                 value: m128i) =
    mm_store_si128(cast[ptr m128i](unsafeAddr data[index]), value)

  template store(t: typedesc[m128i], data: var openArray[uint64], index: int,
                 value: m128i) =
    mm_store_si128(cast[ptr m128i](unsafeAddr data[index]), value)

  template ROUND256(w, x) =
    var t = x + w[7] + TAU1(w[4])
    t = t + CH0(w[4], w[5], w[6])
    w[7] = t + TAU0(w[0]) + MAJ0(w[0], w[1], w[2])
    w[3] = w[3] + t
    let tmp = w[7]
    w[7] = w[6]; w[6] = w[5]; w[5] = w[4]; w[4] = w[3]
    w[3] = w[2]; w[2] = w[1]; w[1] = w[0]; w[0] = tmp

  template ROUND512(w, x) =
    var t = x + w[7] + PHI1(w[4])
    t = t + CH1(w[4], w[5], w[6])
    w[7] = t + PHI0(w[0]) + MAJ1(w[0], w[1], w[2])
    w[3] = w[3] + t
    let tmp = w[7]
    w[7] = w[6]; w[6] = w[5]; w[5] = w[4]; w[4] = w[3]
    w[3] = w[2]; w[2] = w[1]; w[1] = w[0]; w[0] = tmp

  proc sha256UpdateAvx(x: var array[4, m128i], k256i: int,
                       loMask, hiMask: m128i): m128i {.inline, noinit.} =
    var t {.align(64).}: array[4, m128i]

    t[0] = mm_alignr_epi8(x[1], x[0], 4)
    t[3] = mm_alignr_epi8(x[3], x[2], 4)
    t[2] = mm_srli_epi32(t[0], 7)
    x[0] = mm_add_epi32(x[0], t[3])

    t[3] = mm_srli_epi32(t[0], 3)
    t[1] = mm_slli_epi32(t[0], 32 - 18)
    t[0] = mm_xor_si128(t[3], t[2])

    t[3] = mm_shuffle_epi32(x[3], 0xFA'u32)
    t[2] = mm_srli_epi32(t[2], 18 - 7)
    t[0] = mm_xor_si128(t[0], mm_xor_si128(t[1], t[2]))

    t[1] = mm_slli_epi32(t[1], 18 - 7)
    t[2] = mm_srli_epi32(t[3], 10)
    t[3] = mm_srli_epi64(t[3], 17)
    x[0] = mm_add_epi32(x[0], mm_xor_si128(t[0], t[1]))

    t[2] = mm_xor_si128(t[2], t[3])
    t[3] = mm_srli_epi64(t[3], 19 - 17)
    t[2] = mm_shuffle_epi8(mm_xor_si128(t[2], t[3]), loMask)
    x[0] = mm_add_epi32(x[0], t[2])

    t[3] = mm_shuffle_epi32(x[0], 0x50'u32)
    t[2] = mm_srli_epi32(t[3], 10)
    t[3] = mm_srli_epi64(t[3], 17)
    t[2] = mm_xor_si128(t[2], t[3])

    t[3] = mm_srli_epi64(t[3], 19 - 17)
    x[0] = mm_add_epi32(x[0], mm_shuffle_epi8(mm_xor_si128(t[2], t[3]), hiMask))

    let tmp = x[0]; x[0] = x[1]; x[1] = x[2]; x[2] = x[3]; x[3] = tmp

    mm_add_epi32(x[3], m128i.load(K0D, k256i))

  proc sha512UpdateAvx(x: var array[8, m128i], k512i: int): m128i {.
       inline, noinit.} =
    var t {.align(64).}: array[4, m128i]

    t[0] = mm_alignr_epi8(x[1], x[0], 8)
    t[3] = mm_alignr_epi8(x[5], x[4], 8)
    t[2] = mm_srli_epi64(t[0], 1)
    x[0] = mm_add_epi64(x[0], t[3])

    t[3] = mm_srli_epi64(t[0], 7)
    t[1] = mm_slli_epi64(t[0], 64 - 8)
    t[0] = mm_xor_si128(t[3], t[2])

    t[2] = mm_srli_epi64(t[2], 8 - 1)
    t[0] = mm_xor_si128(t[0], t[1])

    t[1] = mm_slli_epi64(t[1], 8 - 1)
    t[0] = mm_xor_si128(t[0], mm_xor_si128(t[2], t[1]))
    t[3] = mm_srli_epi64(x[7], 6)
    t[2] = mm_slli_epi64(x[7], 64 - 61)
    x[0] = mm_add_epi64(x[0], t[0])
    t[1] = mm_srli_epi64(x[7], 19)
    t[3] = mm_xor_si128(t[3], t[2])

    t[2] = mm_slli_epi64(t[2], 61 - 19)
    t[3] = mm_xor_si128(t[3], t[1])

    t[1] = mm_srli_epi64(t[1], 61 - 19)
    t[3] = mm_xor_si128(t[3], mm_xor_si128(t[2], t[1]))

    x[0] = mm_add_epi64(x[0], t[3])

    let tmp = x[0]
    x[0] = x[1]; x[1] = x[2]; x[2] = x[3]; x[3] = x[4];
    x[4] = x[5]; x[5] = x[6]; x[6] = x[7]; x[7] = tmp;

    mm_add_epi64(x[7], m128i.load(K1D, k512i))

  proc loadData32(x: var array[4, m128i],
                  ms: var array[16, uint32], data: openArray[byte]) {.
       inline, noinit.} =
    let shuffleMask =
      mm_setr_epi32(0x00010203'u32, 0x04050607'u32,
                    0x08090a0b'u32, 0x0c0d0e0f'u32)
    x[0] = m128i.load(data, 0)
    x[0] = mm_shuffle_epi8(x[0], shuffleMask)
    m128i.store(ms, 0, mm_add_epi32(x[0], m128i.load(K0D, 0)))

    x[1] = m128i.load(data, 16)
    x[1] = mm_shuffle_epi8(x[1], shuffleMask)
    m128i.store(ms, 4, mm_add_epi32(x[1], m128i.load(K0D, 4)))

    x[2] = m128i.load(data, 32)
    x[2] = mm_shuffle_epi8(x[2], shuffleMask)
    m128i.store(ms, 8, mm_add_epi32(x[2], m128i.load(K0D, 8)))

    x[3] = m128i.load(data, 48)
    x[3] = mm_shuffle_epi8(x[3], shuffleMask)
    m128i.store(ms, 12, mm_add_epi32(x[3], m128i.load(K0D, 12)))

  proc loadData64(x: var array[8, m128i],
                  ms: var array[16, uint64], data: openArray[byte]) {.
       inline, noinit.} =
    let shuffleMask =
      mm_setr_epi32(0x04050607'u32, 0x00010203'u32,
                    0x0c0d0e0f'u32, 0x08090a0b'u32)

    x[0] = m128i.load(data, 0)
    x[0] = mm_shuffle_epi8(x[0], shuffleMask)
    m128i.store(ms, 0, mm_add_epi64(x[0], m128i.load(K1D, 0)))

    x[1] = m128i.load(data, 16)
    x[1] = mm_shuffle_epi8(x[1], shuffleMask)
    m128i.store(ms, 2, mm_add_epi64(x[1], m128i.load(K1D, 2)))

    x[2] = m128i.load(data, 32)
    x[2] = mm_shuffle_epi8(x[2], shuffleMask)
    m128i.store(ms, 4, mm_add_epi64(x[2], m128i.load(K1D, 4)))

    x[3] = m128i.load(data, 48)
    x[3] = mm_shuffle_epi8(x[3], shuffleMask)
    m128i.store(ms, 6, mm_add_epi64(x[3], m128i.load(K1D, 6)))

    x[4] = m128i.load(data, 64)
    x[4] = mm_shuffle_epi8(x[4], shuffleMask)
    m128i.store(ms, 8, mm_add_epi64(x[4], m128i.load(K1D, 8)))

    x[5] = m128i.load(data, 80)
    x[5] = mm_shuffle_epi8(x[5], shuffleMask)
    m128i.store(ms, 10, mm_add_epi64(x[5], m128i.load(K1D, 10)))

    x[6] = m128i.load(data, 96)
    x[6] = mm_shuffle_epi8(x[6], shuffleMask)
    m128i.store(ms, 12, mm_add_epi64(x[6], m128i.load(K1D, 12)))

    x[7] = m128i.load(data, 112)
    x[7] = mm_shuffle_epi8(x[7], shuffleMask)
    m128i.store(ms, 14, mm_add_epi64(x[7], m128i.load(K1D, 14)))

  proc sha256Compress*(state: var array[8, uint32],
                       data: openArray[byte],
                       blocks: int) {.inline, noinit.} =
    let
      loMask =
        mm_setr_epi32(0x03020100'u32, 0x0b0a0908'u32, 0xffffffff'u32,
                      0xffffffff'u32)
      hiMask =
        mm_setr_epi32(0xffffffff'u32, 0xffffffff'u32, 0x03020100'u32,
                      0x0b0a0908'u32)

    var
      ms {.align(64).}: array[16, uint32]
      x {.align(64).}: array[4, m128i]
      cs {.align(64).}: array[8, uint32]
      blocksCount = blocks
      offset = 0

    while blocksCount > 0:
      cs[0] = state[0]; cs[1] = state[1]; cs[2] = state[2]; cs[3] = state[3]
      cs[4] = state[4]; cs[5] = state[5]; cs[6] = state[6]; cs[7] = state[7]

      loadData32(x, ms, data.toOpenArray(offset,
                                         offset + sha256.sizeBlock() - 1))

      block:
        let s0 = sha256UpdateAvx(x, 16, loMask, hiMask)
        ROUND256(cs, ms[0])
        ROUND256(cs, ms[1])
        ROUND256(cs, ms[2])
        ROUND256(cs, ms[3])
        m128i.store(ms, 0, s0)

        let s1 = sha256UpdateAvx(x, 20, loMask, hiMask)
        ROUND256(cs, ms[4])
        ROUND256(cs, ms[5])
        ROUND256(cs, ms[6])
        ROUND256(cs, ms[7])
        m128i.store(ms, 4, s1)

        let s2 = sha256UpdateAvx(x, 24, loMask, hiMask)
        ROUND256(cs, ms[8])
        ROUND256(cs, ms[9])
        ROUND256(cs, ms[10])
        ROUND256(cs, ms[11])
        m128i.store(ms, 8, s2)

        let s3 = sha256UpdateAvx(x, 28, loMask, hiMask)
        ROUND256(cs, ms[12])
        ROUND256(cs, ms[13])
        ROUND256(cs, ms[14])
        ROUND256(cs, ms[15])
        m128i.store(ms, 12, s3)

      block:
        let s0 = sha256UpdateAvx(x, 32, loMask, hiMask)
        ROUND256(cs, ms[0])
        ROUND256(cs, ms[1])
        ROUND256(cs, ms[2])
        ROUND256(cs, ms[3])
        m128i.store(ms, 0, s0)

        let s1 = sha256UpdateAvx(x, 36, loMask, hiMask)
        ROUND256(cs, ms[4])
        ROUND256(cs, ms[5])
        ROUND256(cs, ms[6])
        ROUND256(cs, ms[7])
        m128i.store(ms, 4, s1)

        let s2 = sha256UpdateAvx(x, 40, loMask, hiMask)
        ROUND256(cs, ms[8])
        ROUND256(cs, ms[9])
        ROUND256(cs, ms[10])
        ROUND256(cs, ms[11])
        m128i.store(ms, 8, s2)

        let s3 = sha256UpdateAvx(x, 44, loMask, hiMask)
        ROUND256(cs, ms[12])
        ROUND256(cs, ms[13])
        ROUND256(cs, ms[14])
        ROUND256(cs, ms[15])
        m128i.store(ms, 12, s3)

      block:
        let s0 = sha256UpdateAvx(x, 48, loMask, hiMask)
        ROUND256(cs, ms[0])
        ROUND256(cs, ms[1])
        ROUND256(cs, ms[2])
        ROUND256(cs, ms[3])
        m128i.store(ms, 0, s0)

        let s1 = sha256UpdateAvx(x, 52, loMask, hiMask)
        ROUND256(cs, ms[4])
        ROUND256(cs, ms[5])
        ROUND256(cs, ms[6])
        ROUND256(cs, ms[7])
        m128i.store(ms, 4, s1)

        let s2 = sha256UpdateAvx(x, 56, loMask, hiMask)
        ROUND256(cs, ms[8])
        ROUND256(cs, ms[9])
        ROUND256(cs, ms[10])
        ROUND256(cs, ms[11])
        m128i.store(ms, 8, s2)

        let s3 = sha256UpdateAvx(x, 60, loMask, hiMask)
        ROUND256(cs, ms[12])
        ROUND256(cs, ms[13])
        ROUND256(cs, ms[14])
        ROUND256(cs, ms[15])
        m128i.store(ms, 12, s3)

      ROUND256(cs, ms[0])
      ROUND256(cs, ms[1])
      ROUND256(cs, ms[2])
      ROUND256(cs, ms[3])
      ROUND256(cs, ms[4])
      ROUND256(cs, ms[5])
      ROUND256(cs, ms[6])
      ROUND256(cs, ms[7])
      ROUND256(cs, ms[8])
      ROUND256(cs, ms[9])
      ROUND256(cs, ms[10])
      ROUND256(cs, ms[11])
      ROUND256(cs, ms[12])
      ROUND256(cs, ms[13])
      ROUND256(cs, ms[14])
      ROUND256(cs, ms[15])

      state[0] += cs[0]; state[1] += cs[1]; state[2] += cs[2]; state[3] += cs[3]
      state[4] += cs[4]; state[5] += cs[5]; state[6] += cs[6]; state[7] += cs[7]

      offset += sha256.sizeBlock()
      dec(blocksCount)

  proc sha512Compress*(state: var array[8, uint64],
                       data: openArray[byte],
                       blocks: int) {.inline, noinit.} =
    var
      ms {.align(64).}: array[16, uint64]
      x {.align(64).}: array[8, m128i]
      cs {.align(64).}: array[8, uint64]
      blocksCount = blocks
      offset = 0

    while blocksCount > 0:
      cs[0] = state[0]; cs[1] = state[1]; cs[2] = state[2]; cs[3] = state[3]
      cs[4] = state[4]; cs[5] = state[5]; cs[6] = state[6]; cs[7] = state[7]

      loadData64(x, ms, data.toOpenArray(offset,
                                         offset + sha512.sizeBlock() - 1))

      block:
        let s0 = sha512UpdateAvx(x, 16)
        ROUND512(cs, ms[0])
        ROUND512(cs, ms[1])
        m128i.store(ms, 0, s0)

        let s1 = sha512UpdateAvx(x, 18)
        ROUND512(cs, ms[2])
        ROUND512(cs, ms[3])
        m128i.store(ms, 2, s1)

        let s2 = sha512UpdateAvx(x, 20)
        ROUND512(cs, ms[4])
        ROUND512(cs, ms[5])
        m128i.store(ms, 4, s2)

        let s3 = sha512UpdateAvx(x, 22)
        ROUND512(cs, ms[6])
        ROUND512(cs, ms[7])
        m128i.store(ms, 6, s3)

        let s4 = sha512UpdateAvx(x, 24)
        ROUND512(cs, ms[8])
        ROUND512(cs, ms[9])
        m128i.store(ms, 8, s4)

        let s5 = sha512UpdateAvx(x, 26)
        ROUND512(cs, ms[10])
        ROUND512(cs, ms[11])
        m128i.store(ms, 10, s5)

        let s6 = sha512UpdateAvx(x, 28)
        ROUND512(cs, ms[12])
        ROUND512(cs, ms[13])
        m128i.store(ms, 12, s6)

        let s7 = sha512UpdateAvx(x, 30)
        ROUND512(cs, ms[14])
        ROUND512(cs, ms[15])
        m128i.store(ms, 14, s7)

      block:
        let s0 = sha512UpdateAvx(x, 32)
        ROUND512(cs, ms[0])
        ROUND512(cs, ms[1])
        m128i.store(ms, 0, s0)

        let s1 = sha512UpdateAvx(x, 34)
        ROUND512(cs, ms[2])
        ROUND512(cs, ms[3])
        m128i.store(ms, 2, s1)

        let s2 = sha512UpdateAvx(x, 36)
        ROUND512(cs, ms[4])
        ROUND512(cs, ms[5])
        m128i.store(ms, 4, s2)

        let s3 = sha512UpdateAvx(x, 38)
        ROUND512(cs, ms[6])
        ROUND512(cs, ms[7])
        m128i.store(ms, 6, s3)

        let s4 = sha512UpdateAvx(x, 40)
        ROUND512(cs, ms[8])
        ROUND512(cs, ms[9])
        m128i.store(ms, 8, s4)

        let s5 = sha512UpdateAvx(x, 42)
        ROUND512(cs, ms[10])
        ROUND512(cs, ms[11])
        m128i.store(ms, 10, s5)

        let s6 = sha512UpdateAvx(x, 44)
        ROUND512(cs, ms[12])
        ROUND512(cs, ms[13])
        m128i.store(ms, 12, s6)

        let s7 = sha512UpdateAvx(x, 46)
        ROUND512(cs, ms[14])
        ROUND512(cs, ms[15])
        m128i.store(ms, 14, s7)

      block:
        let s0 = sha512UpdateAvx(x, 48)
        ROUND512(cs, ms[0])
        ROUND512(cs, ms[1])
        m128i.store(ms, 0, s0)

        let s1 = sha512UpdateAvx(x, 50)
        ROUND512(cs, ms[2])
        ROUND512(cs, ms[3])
        m128i.store(ms, 2, s1)

        let s2 = sha512UpdateAvx(x, 52)
        ROUND512(cs, ms[4])
        ROUND512(cs, ms[5])
        m128i.store(ms, 4, s2)

        let s3 = sha512UpdateAvx(x, 54)
        ROUND512(cs, ms[6])
        ROUND512(cs, ms[7])
        m128i.store(ms, 6, s3)

        let s4 = sha512UpdateAvx(x, 56)
        ROUND512(cs, ms[8])
        ROUND512(cs, ms[9])
        m128i.store(ms, 8, s4)

        let s5 = sha512UpdateAvx(x, 58)
        ROUND512(cs, ms[10])
        ROUND512(cs, ms[11])
        m128i.store(ms, 10, s5)

        let s6 = sha512UpdateAvx(x, 60)
        ROUND512(cs, ms[12])
        ROUND512(cs, ms[13])
        m128i.store(ms, 12, s6)

        let s7 = sha512UpdateAvx(x, 62)
        ROUND512(cs, ms[14])
        ROUND512(cs, ms[15])
        m128i.store(ms, 14, s7)

      block:
        let s0 = sha512UpdateAvx(x, 64)
        ROUND512(cs, ms[0])
        ROUND512(cs, ms[1])
        m128i.store(ms, 0, s0)

        let s1 = sha512UpdateAvx(x, 66)
        ROUND512(cs, ms[2])
        ROUND512(cs, ms[3])
        m128i.store(ms, 2, s1)

        let s2 = sha512UpdateAvx(x, 68)
        ROUND512(cs, ms[4])
        ROUND512(cs, ms[5])
        m128i.store(ms, 4, s2)

        let s3 = sha512UpdateAvx(x, 70)
        ROUND512(cs, ms[6])
        ROUND512(cs, ms[7])
        m128i.store(ms, 6, s3)

        let s4 = sha512UpdateAvx(x, 72)
        ROUND512(cs, ms[8])
        ROUND512(cs, ms[9])
        m128i.store(ms, 8, s4)

        let s5 = sha512UpdateAvx(x, 74)
        ROUND512(cs, ms[10])
        ROUND512(cs, ms[11])
        m128i.store(ms, 10, s5)

        let s6 = sha512UpdateAvx(x, 76)
        ROUND512(cs, ms[12])
        ROUND512(cs, ms[13])
        m128i.store(ms, 12, s6)

        let s7 = sha512UpdateAvx(x, 78)
        ROUND512(cs, ms[14])
        ROUND512(cs, ms[15])
        m128i.store(ms, 14, s7)

      ROUND512(cs, ms[0])
      ROUND512(cs, ms[1])
      ROUND512(cs, ms[2])
      ROUND512(cs, ms[3])
      ROUND512(cs, ms[4])
      ROUND512(cs, ms[5])
      ROUND512(cs, ms[6])
      ROUND512(cs, ms[7])
      ROUND512(cs, ms[8])
      ROUND512(cs, ms[9])
      ROUND512(cs, ms[10])
      ROUND512(cs, ms[11])
      ROUND512(cs, ms[12])
      ROUND512(cs, ms[13])
      ROUND512(cs, ms[14])
      ROUND512(cs, ms[15])

      state[0] += cs[0]; state[1] += cs[1]; state[2] += cs[2]; state[3] += cs[3]
      state[4] += cs[4]; state[5] += cs[5]; state[6] += cs[6]; state[7] += cs[7]

      offset += sha512.sizeBlock()
      dec(blocksCount)
