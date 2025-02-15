#
#
#                    NimCrypto
#        (c) Copyright 2024 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module is optimized SHA2-256 (Secure Hash Algorithm 2) implementation
## for AMD64 using CPU AVX2 extension.
##
## This implementation is Nim version of C code by Nir Drucker and Shay Gueron
## (AWS Cryptographic Algorithms Group. (ndrucker@amazon.com,
## gueron@amazon.com)).
## https://github.com/aws-samples/sha2-with-c-intrinsic/blob/master/src/sha256_compress_x86_64_avx2.c
##
## Which is based on Gueron, S., Krasnov, V.
## Parallelizing message schedules to accelerate the computations of hash
## functions. J Cryptogr Eng 2, 241–253 (2012).
## https://doi.org/10.1007/s13389-012-0037-z

{.push raises: [].}
{.used.}

when defined(amd64):
  import "."/[sha2_common, sha2_avx]

  {.localPassc:"-mavx2".}

  when defined(vcc):
    {.pragma: x86type, bycopy, header:"<intrin.h>".}
    {.pragma: x86proc, nodecl, header:"<intrin.h>".}
  else:
    {.pragma: x86type, bycopy, header:"<x86intrin.h>".}
    {.pragma: x86proc, nodecl, header:"<x86intrin.h>".}

  const
    SHA2_AVX2_sha256Compress* = true
    SHA2_AVX2_sha512Compress* = true

  type
    m256i* {.importc: "__m256i", x86type.} = object
      data: array[4, uint64]
    m128i* {.importc: "__m128i", x86type.} = object
      data: array[2, uint64]

  let
    K0x2 {.align(64).} = [
      K0[ 0], K0[ 1], K0[ 2], K0[ 3], K0[ 0], K0[ 1], K0[ 2], K0[ 3],
      K0[ 4], K0[ 5], K0[ 6], K0[ 7], K0[ 4], K0[ 5], K0[ 6], K0[ 7],
      K0[ 8], K0[ 9], K0[10], K0[11], K0[ 8], K0[ 9], K0[10], K0[11],
      K0[12], K0[13], K0[14], K0[15], K0[12], K0[13], K0[14], K0[15],
      K0[16], K0[17], K0[18], K0[19], K0[16], K0[17], K0[18], K0[19],
      K0[20], K0[21], K0[22], K0[23], K0[20], K0[21], K0[22], K0[23],
      K0[24], K0[25], K0[26], K0[27], K0[24], K0[25], K0[26], K0[27],
      K0[28], K0[29], K0[30], K0[31], K0[28], K0[29], K0[30], K0[31],
      K0[32], K0[33], K0[34], K0[35], K0[32], K0[33], K0[34], K0[35],
      K0[36], K0[37], K0[38], K0[39], K0[36], K0[37], K0[38], K0[39],
      K0[40], K0[41], K0[42], K0[43], K0[40], K0[41], K0[42], K0[43],
      K0[44], K0[45], K0[46], K0[47], K0[44], K0[45], K0[46], K0[47],
      K0[48], K0[49], K0[50], K0[51], K0[48], K0[49], K0[50], K0[51],
      K0[52], K0[53], K0[54], K0[55], K0[52], K0[53], K0[54], K0[55],
      K0[56], K0[57], K0[58], K0[59], K0[56], K0[57], K0[58], K0[59],
      K0[60], K0[61], K0[62], K0[63], K0[60], K0[61], K0[62], K0[63]
    ]
    K1x2 {.align(64).} = [
      K1[ 0], K1[ 1], K1[ 0], K1[ 1], K1[ 2], K1[ 3], K1[ 2], K1[ 3],
      K1[ 4], K1[ 5], K1[ 4], K1[ 5], K1[ 6], K1[ 7], K1[ 6], K1[ 7],
      K1[ 8], K1[ 9], K1[ 8], K1[ 9], K1[10], K1[11], K1[10], K1[11],
      K1[12], K1[13], K1[12], K1[13], K1[14], K1[15], K1[14], K1[15],
      K1[16], K1[17], K1[16], K1[17], K1[18], K1[19], K1[18], K1[19],
      K1[20], K1[21], K1[20], K1[21], K1[22], K1[23], K1[22], K1[23],
      K1[24], K1[25], K1[24], K1[25], K1[26], K1[27], K1[26], K1[27],
      K1[28], K1[29], K1[28], K1[29], K1[30], K1[31], K1[30], K1[31],
      K1[32], K1[33], K1[32], K1[33], K1[34], K1[35], K1[34], K1[35],
      K1[36], K1[37], K1[36], K1[37], K1[38], K1[39], K1[38], K1[39],
      K1[40], K1[41], K1[40], K1[41], K1[42], K1[43], K1[42], K1[43],
      K1[44], K1[45], K1[44], K1[45], K1[46], K1[47], K1[46], K1[47],
      K1[48], K1[49], K1[48], K1[49], K1[50], K1[51], K1[50], K1[51],
      K1[52], K1[53], K1[52], K1[53], K1[54], K1[55], K1[54], K1[55],
      K1[56], K1[57], K1[56], K1[57], K1[58], K1[59], K1[58], K1[59],
      K1[60], K1[61], K1[60], K1[61], K1[62], K1[63], K1[62], K1[63],
      K1[64], K1[65], K1[64], K1[65], K1[66], K1[67], K1[66], K1[67],
      K1[68], K1[69], K1[68], K1[69], K1[70], K1[71], K1[70], K1[71],
      K1[72], K1[73], K1[72], K1[73], K1[74], K1[75], K1[74], K1[75],
      K1[76], K1[77], K1[76], K1[77], K1[78], K1[79], K1[78], K1[79]
    ]

  func mm256_add_epi32(a, b: m256i): m256i {.
       importc: "_mm256_add_epi32", x86proc.}
  func mm256_add_epi64(a, b: m256i): m256i {.
       importc: "_mm256_add_epi64", x86proc.}
  func mm256_setr_epi32(e7, e6, e5, e4, e3, e2, e1, e0: uint32): m256i {.
       importc: "_mm256_setr_epi32", x86proc.}
  func mm256_set_epi64x(e3, e2, e1, e0: uint64): m256i {.
       importc: "_mm256_set_epi64x", x86proc.}
  func mm256_alignr_epi8(a, b: m256i, imm8: uint32): m256i {.
       importc: "_mm256_alignr_epi8", x86proc.}
  func mm256_loadu_si256(a: ptr m256i): m256i {.
       importc: "_mm256_loadu_si256", x86proc.}
  func mm256_shuffle_epi8(a, b: m256i): m256i {.
       importc: "_mm256_shuffle_epi8", x86proc.}
  func mm256_shuffle_epi32(a: m256i, imm8: uint32): m256i {.
       importc: "_mm256_shuffle_epi32", x86proc.}
  func mm256_slli_epi32(a: m256i, imm8: uint32): m256i {.
       importc: "_mm256_slli_epi32", x86proc.}
  func mm256_slli_epi64(a: m256i, imm8: uint32): m256i {.
       importc: "_mm256_slli_epi64", x86proc.}
  func mm256_srli_epi32(a: m256i, imm8: uint32): m256i {.
       importc: "_mm256_srli_epi32", x86proc.}
  func mm256_srli_epi64(a: m256i, imm8: uint32): m256i {.
       importc: "_mm256_srli_epi64", x86proc.}
  func mm256_loadu2_m128i(hi: ptr m128i, lo: ptr m128i): m256i {.
       importc: "_mm256_loadu2_m128i", x86proc.}
  func mm256_storeu2_m128i(hi: ptr m128i, lo: ptr m128i, a: m256i) {.
       importc: "_mm256_storeu2_m128i", x86proc.}
  func mm256_xor_si256(a, b: m256i): m256i {.
       importc: "_mm256_xor_si256", x86proc.}

  template load(t: typedesc[m256i], data1: openArray[byte], x1: int,
                data2: openArray[byte], x2: int): m256i =
    mm256_loadu2_m128i(
      cast[ptr m128i](unsafeAddr data1[x1]),
      cast[ptr m128i](unsafeAddr data2[x2]))

  template load(t: typedesc[m256i], data: openArray[uint32], i: int): m256i =
    mm256_loadu_si256(cast[ptr m256i](unsafeAddr data[i]))

  template load(t: typedesc[m256i], data: openArray[uint64], i: int): m256i =
    mm256_loadu_si256(cast[ptr m256i](unsafeAddr data[i]))

  template store(t: typedesc[m256i], data1: var openArray[uint32], x1: int,
                 data2: var openArray[uint32], x2: int, a: m256i) =
    mm256_storeu2_m128i(
      cast[ptr m128i](unsafeAddr data1[x1]),
      cast[ptr m128i](unsafeAddr data2[x2]),
      a)

  template store(t: typedesc[m256i], data1: var openArray[uint64], x1: int,
                 data2: var openArray[uint64], x2: int, a: m256i) =
    mm256_storeu2_m128i(
      cast[ptr m128i](unsafeAddr data1[x1]),
      cast[ptr m128i](unsafeAddr data2[x2]),
      a)

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

  template sha256UpdateAvx2(x, k256i, loMask, hiMask: untyped): m256i =
    var t {.align(32), noinit.}: array[4, m256i]

    t[0] = mm256_alignr_epi8(x[1], x[0], 4)
    t[3] = mm256_alignr_epi8(x[3], x[2], 4)
    t[2] = mm256_srli_epi32(t[0], 7)
    x[0] = mm256_add_epi32(x[0], t[3])

    t[3] = mm256_srli_epi32(t[0], 3)
    t[1] = mm256_slli_epi32(t[0], 32 - 18)
    t[0] = mm256_xor_si256(t[3], t[2])

    t[3] = mm256_shuffle_epi32(x[3], 0xFA'u32)
    t[2] = mm256_srli_epi32(t[2], 18 - 7)
    t[0] = mm256_xor_si256(t[0], mm256_xor_si256(t[1], t[2]))

    t[1] = mm256_slli_epi32(t[1], 18 - 7)
    t[2] = mm256_srli_epi32(t[3], 10)
    t[3] = mm256_srli_epi64(t[3], 17)
    x[0] = mm256_add_epi32(x[0], mm256_xor_si256(t[0], t[1]))

    t[2] = mm256_xor_si256(t[2], t[3])
    t[3] = mm256_srli_epi64(t[3], 19 - 17)
    t[2] = mm256_shuffle_epi8(mm256_xor_si256(t[2], t[3]), loMask)
    x[0] = mm256_add_epi32(x[0], t[2])

    t[3] = mm256_shuffle_epi32(x[0], 0x50'u32)
    t[2] = mm256_srli_epi32(t[3], 10)
    t[3] = mm256_srli_epi64(t[3], 17)
    t[2] = mm256_xor_si256(t[2], t[3])

    t[3] = mm256_srli_epi64(t[3], 19 - 17)
    x[0] = mm256_add_epi32(x[0],
             mm256_shuffle_epi8(mm256_xor_si256(t[2], t[3]), hiMask))

    let tmp = x[0]; x[0] = x[1]; x[1] = x[2]; x[2] = x[3]; x[3] = tmp

    mm256_add_epi32(x[3], m256i.load(K0x2, k256i))

  template sha512UpdateAvx2(x, k512i: untyped): m256i =
    var t {.align(32), noinit.}: array[4, m256i]

    t[0] = mm256_alignr_epi8(x[1], x[0], 8)
    t[3] = mm256_alignr_epi8(x[5], x[4], 8)
    t[2] = mm256_srli_epi64(t[0], 1)
    x[0] = mm256_add_epi64(x[0], t[3])

    t[3] = mm256_srli_epi64(t[0], 7)
    t[1] = mm256_slli_epi64(t[0], 64 - 8)
    t[0] = mm256_xor_si256(t[3], t[2])

    t[2] = mm256_srli_epi64(t[2], 8 - 1)
    t[0] = mm256_xor_si256(t[0], t[1])

    t[1] = mm256_slli_epi64(t[1], 8 - 1)
    t[0] = mm256_xor_si256(t[0], mm256_xor_si256(t[2], t[1]))
    t[3] = mm256_srli_epi64(x[7], 6)
    t[2] = mm256_slli_epi64(x[7], 64 - 61)
    x[0] = mm256_add_epi64(x[0], t[0])
    t[1] = mm256_srli_epi64(x[7], 19)
    t[3] = mm256_xor_si256(t[3], t[2])

    t[2] = mm256_slli_epi64(t[2], 61 - 19)
    t[3] = mm256_xor_si256(t[3], t[1])

    t[1] = mm256_srli_epi64(t[1], 61 - 19)
    t[3] = mm256_xor_si256(t[3], mm256_xor_si256(t[2], t[1]))

    x[0] = mm256_add_epi64(x[0], t[3])

    let tmp = x[0]
    x[0] = x[1]; x[1] = x[2]; x[2] = x[3]; x[3] = x[4];
    x[4] = x[5]; x[5] = x[6]; x[6] = x[7]; x[7] = tmp;

    mm256_add_epi64(x[7], m256i.load(K1x2, k512i))

  template loadData32(x, ms, t2: untyped,
                      data: openArray[byte]) =
    let shuffleMask {.align(32).} =
      mm256_setr_epi32(0x00010203'u32, 0x04050607'u32,
                       0x08090a0b'u32, 0x0c0d0e0f'u32,
                       0x00010203'u32, 0x04050607'u32,
                       0x08090a0b'u32, 0x0c0d0e0f'u32)

    block:
      x[0] = m256i.load(data, 64, data, 0)
      x[0] = mm256_shuffle_epi8(x[0], shuffleMask)
      let y {.align(32).} = mm256_add_epi32(x[0], m256i.load(K0x2, 0))
      m256i.store(t2, 0, ms, 0, y)

    block:
      x[1] = m256i.load(data, 80, data, 16)
      x[1] = mm256_shuffle_epi8(x[1], shuffleMask)
      let y {.align(32).} = mm256_add_epi32(x[1], m256i.load(K0x2, 8))
      m256i.store(t2, 4, ms, 4, y)

    block:
      x[2] = m256i.load(data, 96, data, 32)
      x[2] = mm256_shuffle_epi8(x[2], shuffleMask)
      let y {.align(32).} = mm256_add_epi32(x[2], m256i.load(K0x2, 16))
      m256i.store(t2, 8, ms, 8, y)

    block:
      x[3] = m256i.load(data, 112, data, 48)
      x[3] = mm256_shuffle_epi8(x[3], shuffleMask)
      let y {.align(32).} = mm256_add_epi32(x[3], m256i.load(K0x2, 24))
      m256i.store(t2, 12, ms, 12, y)

  template loadData64(x, ms, t2: untyped,
                      data: openArray[byte]) =
    let shuffleMask {.align(32).} =
      mm256_set_epi64x(0x08090a0b0c0d0e0f'u64, 0x0001020304050607'u64,
                       0x08090a0b0c0d0e0f'u64, 0x0001020304050607'u64)

    block:
      x[0] = m256i.load(data, 128, data, 0)
      x[0] = mm256_shuffle_epi8(x[0], shuffleMask)
      let y {.align(32).} = mm256_add_epi64(x[0], m256i.load(K1x2, 0))
      m256i.store(t2, 0, ms, 0, y)

    block:
      x[1] = m256i.load(data, 144, data, 16)
      x[1] = mm256_shuffle_epi8(x[1], shuffleMask)
      let y {.align(32).} = mm256_add_epi64(x[1], m256i.load(K1x2, 4))
      m256i.store(t2, 2, ms, 2, y)

    block:
      x[2] = m256i.load(data, 160, data, 32)
      x[2] = mm256_shuffle_epi8(x[2], shuffleMask)
      let y {.align(32).} = mm256_add_epi64(x[2], m256i.load(K1x2, 8))
      m256i.store(t2, 4, ms, 4, y)

    block:
      x[3] = m256i.load(data, 176, data, 48)
      x[3] = mm256_shuffle_epi8(x[3], shuffleMask)
      let y {.align(32).} = mm256_add_epi64(x[3], m256i.load(K1x2, 12))
      m256i.store(t2, 6, ms, 6, y)

    block:
      x[4] = m256i.load(data, 192, data, 64)
      x[4] = mm256_shuffle_epi8(x[4], shuffleMask)
      let y {.align(32).} = mm256_add_epi64(x[4], m256i.load(K1x2, 16))
      m256i.store(t2, 8, ms, 8, y)

    block:
      x[5] = m256i.load(data, 208, data, 80)
      x[5] = mm256_shuffle_epi8(x[5], shuffleMask)
      let y {.align(32).} = mm256_add_epi64(x[5], m256i.load(K1x2, 20))
      m256i.store(t2, 10, ms, 10, y)

    block:
      x[6] = m256i.load(data, 224, data, 96)
      x[6] = mm256_shuffle_epi8(x[6], shuffleMask)
      let y {.align(32).} = mm256_add_epi64(x[6], m256i.load(K1x2, 24))
      m256i.store(t2, 12, ms, 12, y)

    block:
      x[7] = m256i.load(data, 240, data, 112)
      x[7] = mm256_shuffle_epi8(x[7], shuffleMask)
      let y {.align(32).} = mm256_add_epi64(x[7], m256i.load(K1x2, 28))
      m256i.store(t2, 14, ms, 14, y)

  proc sha256Compress*(state: var array[8, uint32],
                       data: openArray[byte],
                       blocks: int) {.inline, noinit.} =
    var
      x {.align(32), noinit.}: array[4, m256i]
      ms {.align(32), noinit.}: array[16, uint32]
      t2 {.align(32), noinit.}: array[64, uint32]
      cs {.align(32), noinit.}: array[8, uint32]
      blocksCount = blocks
      offset = 0

    let
      loMask {.align(32).} =
        mm256_setr_epi32(0x03020100'u32, 0x0b0a0908'u32,
                         0xffffffff'u32, 0xffffffff'u32,
                         0x03020100'u32, 0x0b0a0908'u32,
                         0xffffffff'u32, 0xffffffff'u32)
      hiMask {.align(32).} =
        mm256_setr_epi32(0xffffffff'u32, 0xffffffff'u32,
                         0x03020100'u32, 0x0b0a0908'u32,
                         0xffffffff'u32, 0xffffffff'u32,
                         0x03020100'u32, 0x0b0a0908'u32)

    if (blocksCount and 1) == 1:
      sha2_avx.sha256Compress(state, data, 1)
      offset += sha256.sizeBlock()
      dec(blocksCount)

    while blocksCount > 0:
      cs[0] = state[0]; cs[1] = state[1]; cs[2] = state[2]; cs[3] = state[3]
      cs[4] = state[4]; cs[5] = state[5]; cs[6] = state[6]; cs[7] = state[7]

      loadData32(x, ms, t2,
                 data.toOpenArray(offset, offset + 2 * sha256.sizeBlock() - 1))

      block:
        let s0 {.align(32).} = sha256UpdateAvx2(x, 32, loMask, hiMask)
        ROUND256(cs, ms[0])
        ROUND256(cs, ms[1])
        ROUND256(cs, ms[2])
        ROUND256(cs, ms[3])
        m256i.store(t2, 16, ms, 0, s0)

        let s1 {.align(32).} = sha256UpdateAvx2(x, 40, loMask, hiMask)
        ROUND256(cs, ms[4])
        ROUND256(cs, ms[5])
        ROUND256(cs, ms[6])
        ROUND256(cs, ms[7])
        m256i.store(t2, 20, ms, 4, s1)

        let s2 {.align(32).} = sha256UpdateAvx2(x, 48, loMask, hiMask)
        ROUND256(cs, ms[8])
        ROUND256(cs, ms[9])
        ROUND256(cs, ms[10])
        ROUND256(cs, ms[11])
        m256i.store(t2, 24, ms, 8, s2)

        let s3 {.align(32).} = sha256UpdateAvx2(x, 56, loMask, hiMask)
        ROUND256(cs, ms[12])
        ROUND256(cs, ms[13])
        ROUND256(cs, ms[14])
        ROUND256(cs, ms[15])
        m256i.store(t2, 28, ms, 12, s3)

      block:
        let s0 {.align(32).} = sha256UpdateAvx2(x, 64, loMask, hiMask)
        ROUND256(cs, ms[0])
        ROUND256(cs, ms[1])
        ROUND256(cs, ms[2])
        ROUND256(cs, ms[3])
        m256i.store(t2, 32, ms, 0, s0)

        let s1 {.align(32).} = sha256UpdateAvx2(x, 72, loMask, hiMask)
        ROUND256(cs, ms[4])
        ROUND256(cs, ms[5])
        ROUND256(cs, ms[6])
        ROUND256(cs, ms[7])
        m256i.store(t2, 36, ms, 4, s1)

        let s2 {.align(32).} = sha256UpdateAvx2(x, 80, loMask, hiMask)
        ROUND256(cs, ms[8])
        ROUND256(cs, ms[9])
        ROUND256(cs, ms[10])
        ROUND256(cs, ms[11])
        m256i.store(t2, 40, ms, 8, s2)

        let s3 {.align(32).} = sha256UpdateAvx2(x, 88, loMask, hiMask)
        ROUND256(cs, ms[12])
        ROUND256(cs, ms[13])
        ROUND256(cs, ms[14])
        ROUND256(cs, ms[15])
        m256i.store(t2, 44, ms, 12, s3)

      block:
        let s0 {.align(32).} = sha256UpdateAvx2(x, 96, loMask, hiMask)
        ROUND256(cs, ms[0])
        ROUND256(cs, ms[1])
        ROUND256(cs, ms[2])
        ROUND256(cs, ms[3])
        m256i.store(t2, 48, ms, 0, s0)

        let s1 {.align(32).} = sha256UpdateAvx2(x, 104, loMask, hiMask)
        ROUND256(cs, ms[4])
        ROUND256(cs, ms[5])
        ROUND256(cs, ms[6])
        ROUND256(cs, ms[7])
        m256i.store(t2, 52, ms, 4, s1)

        let s2 {.align(32).} = sha256UpdateAvx2(x, 112, loMask, hiMask)
        ROUND256(cs, ms[8])
        ROUND256(cs, ms[9])
        ROUND256(cs, ms[10])
        ROUND256(cs, ms[11])
        m256i.store(t2, 56, ms, 8, s2)

        let s3 {.align(32).} = sha256UpdateAvx2(x, 120, loMask, hiMask)
        ROUND256(cs, ms[12])
        ROUND256(cs, ms[13])
        ROUND256(cs, ms[14])
        ROUND256(cs, ms[15])
        m256i.store(t2, 60, ms, 12, s3)

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

      # Processing second block

      cs[0] = state[0]; cs[1] = state[1]; cs[2] = state[2]; cs[3] = state[3]
      cs[4] = state[4]; cs[5] = state[5]; cs[6] = state[6]; cs[7] = state[7]

      ROUND256(cs, t2[0])
      ROUND256(cs, t2[1])
      ROUND256(cs, t2[2])
      ROUND256(cs, t2[3])
      ROUND256(cs, t2[4])
      ROUND256(cs, t2[5])
      ROUND256(cs, t2[6])
      ROUND256(cs, t2[7])
      ROUND256(cs, t2[8])
      ROUND256(cs, t2[9])
      ROUND256(cs, t2[10])
      ROUND256(cs, t2[11])
      ROUND256(cs, t2[12])
      ROUND256(cs, t2[13])
      ROUND256(cs, t2[14])
      ROUND256(cs, t2[15])
      ROUND256(cs, t2[16])
      ROUND256(cs, t2[17])
      ROUND256(cs, t2[18])
      ROUND256(cs, t2[19])
      ROUND256(cs, t2[20])
      ROUND256(cs, t2[21])
      ROUND256(cs, t2[22])
      ROUND256(cs, t2[23])
      ROUND256(cs, t2[24])
      ROUND256(cs, t2[25])
      ROUND256(cs, t2[26])
      ROUND256(cs, t2[27])
      ROUND256(cs, t2[28])
      ROUND256(cs, t2[29])
      ROUND256(cs, t2[30])
      ROUND256(cs, t2[31])
      ROUND256(cs, t2[32])
      ROUND256(cs, t2[33])
      ROUND256(cs, t2[34])
      ROUND256(cs, t2[35])
      ROUND256(cs, t2[36])
      ROUND256(cs, t2[37])
      ROUND256(cs, t2[38])
      ROUND256(cs, t2[39])
      ROUND256(cs, t2[40])
      ROUND256(cs, t2[41])
      ROUND256(cs, t2[42])
      ROUND256(cs, t2[43])
      ROUND256(cs, t2[44])
      ROUND256(cs, t2[45])
      ROUND256(cs, t2[46])
      ROUND256(cs, t2[47])
      ROUND256(cs, t2[48])
      ROUND256(cs, t2[49])
      ROUND256(cs, t2[50])
      ROUND256(cs, t2[51])
      ROUND256(cs, t2[52])
      ROUND256(cs, t2[53])
      ROUND256(cs, t2[54])
      ROUND256(cs, t2[55])
      ROUND256(cs, t2[56])
      ROUND256(cs, t2[57])
      ROUND256(cs, t2[58])
      ROUND256(cs, t2[59])
      ROUND256(cs, t2[60])
      ROUND256(cs, t2[61])
      ROUND256(cs, t2[62])
      ROUND256(cs, t2[63])

      state[0] += cs[0]; state[1] += cs[1]; state[2] += cs[2]; state[3] += cs[3]
      state[4] += cs[4]; state[5] += cs[5]; state[6] += cs[6]; state[7] += cs[7]

      offset += (2 * sha256.sizeBlock())
      dec(blocksCount, 2)

  proc sha512Compress*(state: var array[8, uint64],
                       data: openArray[byte],
                       blocks: int) {.inline, noinit.} =
    var
      x {.align(32), noinit.}: array[8, m256i]
      ms {.align(32), noinit.}: array[16, uint64]
      cs {.align(32), noinit.}: array[8, uint64]
      t2 {.align(32), noinit.}: array[80, uint64]
      blocksCount = blocks
      offset = 0

    if (blocksCount and 1) == 1:
      sha2_avx.sha512Compress(state, data, 1)
      offset += sha512.sizeBlock()
      dec(blocksCount)

    while blocksCount > 0:
      cs[0] = state[0]; cs[1] = state[1]; cs[2] = state[2]; cs[3] = state[3]
      cs[4] = state[4]; cs[5] = state[5]; cs[6] = state[6]; cs[7] = state[7]

      loadData64(x, ms, t2,
                 data.toOpenArray(offset, offset + 2 * sha512.sizeBlock() - 1))

      block:
        let s0 {.align(32).} = sha512UpdateAvx2(x, 32)
        ROUND512(cs, ms[0])
        ROUND512(cs, ms[1])
        m256i.store(t2, 16, ms, 0, s0)

        let s1 {.align(32).} = sha512UpdateAvx2(x, 36)
        ROUND512(cs, ms[2])
        ROUND512(cs, ms[3])
        m256i.store(t2, 18, ms, 2, s1)

        let s2 {.align(32).} = sha512UpdateAvx2(x, 40)
        ROUND512(cs, ms[4])
        ROUND512(cs, ms[5])
        m256i.store(t2, 20, ms, 4, s2)

        let s3 {.align(32).} = sha512UpdateAvx2(x, 44)
        ROUND512(cs, ms[6])
        ROUND512(cs, ms[7])
        m256i.store(t2, 22, ms, 6, s3)

        let s4 {.align(32).} = sha512UpdateAvx2(x, 48)
        ROUND512(cs, ms[8])
        ROUND512(cs, ms[9])
        m256i.store(t2, 24, ms, 8, s4)

        let s5 {.align(32).} = sha512UpdateAvx2(x, 52)
        ROUND512(cs, ms[10])
        ROUND512(cs, ms[11])
        m256i.store(t2, 26, ms, 10, s5)

        let s6 {.align(32).} = sha512UpdateAvx2(x, 56)
        ROUND512(cs, ms[12])
        ROUND512(cs, ms[13])
        m256i.store(t2, 28, ms, 12, s6)

        let s7 {.align(32).} = sha512UpdateAvx2(x, 60)
        ROUND512(cs, ms[14])
        ROUND512(cs, ms[15])
        m256i.store(t2, 30, ms, 14, s7)

      block:
        let s0 {.align(32).} = sha512UpdateAvx2(x, 64)
        ROUND512(cs, ms[0])
        ROUND512(cs, ms[1])
        m256i.store(t2, 32, ms, 0, s0)

        let s1 {.align(32).} = sha512UpdateAvx2(x, 68)
        ROUND512(cs, ms[2])
        ROUND512(cs, ms[3])
        m256i.store(t2, 34, ms, 2, s1)

        let s2 {.align(32).} = sha512UpdateAvx2(x, 72)
        ROUND512(cs, ms[4])
        ROUND512(cs, ms[5])
        m256i.store(t2, 36, ms, 4, s2)

        let s3 {.align(32).} = sha512UpdateAvx2(x, 76)
        ROUND512(cs, ms[6])
        ROUND512(cs, ms[7])
        m256i.store(t2, 38, ms, 6, s3)

        let s4 {.align(32).} = sha512UpdateAvx2(x, 80)
        ROUND512(cs, ms[8])
        ROUND512(cs, ms[9])
        m256i.store(t2, 40, ms, 8, s4)

        let s5 {.align(32).} = sha512UpdateAvx2(x, 84)
        ROUND512(cs, ms[10])
        ROUND512(cs, ms[11])
        m256i.store(t2, 42, ms, 10, s5)

        let s6 {.align(32).} = sha512UpdateAvx2(x, 88)
        ROUND512(cs, ms[12])
        ROUND512(cs, ms[13])
        m256i.store(t2, 44, ms, 12, s6)

        let s7 {.align(32).} = sha512UpdateAvx2(x, 92)
        ROUND512(cs, ms[14])
        ROUND512(cs, ms[15])
        m256i.store(t2, 46, ms, 14, s7)

      block:
        let s0 {.align(32).} = sha512UpdateAvx2(x, 96)
        ROUND512(cs, ms[0])
        ROUND512(cs, ms[1])
        m256i.store(t2, 48, ms, 0, s0)

        let s1 {.align(32).} = sha512UpdateAvx2(x, 100)
        ROUND512(cs, ms[2])
        ROUND512(cs, ms[3])
        m256i.store(t2, 50, ms, 2, s1)

        let s2 {.align(32).} = sha512UpdateAvx2(x, 104)
        ROUND512(cs, ms[4])
        ROUND512(cs, ms[5])
        m256i.store(t2, 52, ms, 4, s2)

        let s3 {.align(32).} = sha512UpdateAvx2(x, 108)
        ROUND512(cs, ms[6])
        ROUND512(cs, ms[7])
        m256i.store(t2, 54, ms, 6, s3)

        let s4 {.align(32).} = sha512UpdateAvx2(x, 112)
        ROUND512(cs, ms[8])
        ROUND512(cs, ms[9])
        m256i.store(t2, 56, ms, 8, s4)

        let s5 {.align(32).} = sha512UpdateAvx2(x, 116)
        ROUND512(cs, ms[10])
        ROUND512(cs, ms[11])
        m256i.store(t2, 58, ms, 10, s5)

        let s6 {.align(32).} = sha512UpdateAvx2(x, 120)
        ROUND512(cs, ms[12])
        ROUND512(cs, ms[13])
        m256i.store(t2, 60, ms, 12, s6)

        let s7 {.align(32).} = sha512UpdateAvx2(x, 124)
        ROUND512(cs, ms[14])
        ROUND512(cs, ms[15])
        m256i.store(t2, 62, ms, 14, s7)

      block:
        let s0 {.align(32).} = sha512UpdateAvx2(x, 128)
        ROUND512(cs, ms[0])
        ROUND512(cs, ms[1])
        m256i.store(t2, 64, ms, 0, s0)

        let s1 {.align(32).} = sha512UpdateAvx2(x, 132)
        ROUND512(cs, ms[2])
        ROUND512(cs, ms[3])
        m256i.store(t2, 66, ms, 2, s1)

        let s2 {.align(32).} = sha512UpdateAvx2(x, 136)
        ROUND512(cs, ms[4])
        ROUND512(cs, ms[5])
        m256i.store(t2, 68, ms, 4, s2)

        let s3 {.align(32).} = sha512UpdateAvx2(x, 140)
        ROUND512(cs, ms[6])
        ROUND512(cs, ms[7])
        m256i.store(t2, 70, ms, 6, s3)

        let s4 {.align(32).} = sha512UpdateAvx2(x, 144)
        ROUND512(cs, ms[8])
        ROUND512(cs, ms[9])
        m256i.store(t2, 72, ms, 8, s4)

        let s5 {.align(32).} = sha512UpdateAvx2(x, 148)
        ROUND512(cs, ms[10])
        ROUND512(cs, ms[11])
        m256i.store(t2, 74, ms, 10, s5)

        let s6 {.align(32).} = sha512UpdateAvx2(x, 152)
        ROUND512(cs, ms[12])
        ROUND512(cs, ms[13])
        m256i.store(t2, 76, ms, 12, s6)

        let s7 {.align(32).} = sha512UpdateAvx2(x, 156)
        ROUND512(cs, ms[14])
        ROUND512(cs, ms[15])
        m256i.store(t2, 78, ms, 14, s7)

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

      # Processing second block

      cs[0] = state[0]; cs[1] = state[1]; cs[2] = state[2]; cs[3] = state[3]
      cs[4] = state[4]; cs[5] = state[5]; cs[6] = state[6]; cs[7] = state[7]

      ROUND512(cs, t2[0])
      ROUND512(cs, t2[1])
      ROUND512(cs, t2[2])
      ROUND512(cs, t2[3])
      ROUND512(cs, t2[4])
      ROUND512(cs, t2[5])
      ROUND512(cs, t2[6])
      ROUND512(cs, t2[7])
      ROUND512(cs, t2[8])
      ROUND512(cs, t2[9])
      ROUND512(cs, t2[10])
      ROUND512(cs, t2[11])
      ROUND512(cs, t2[12])
      ROUND512(cs, t2[13])
      ROUND512(cs, t2[14])
      ROUND512(cs, t2[15])
      ROUND512(cs, t2[16])
      ROUND512(cs, t2[17])
      ROUND512(cs, t2[18])
      ROUND512(cs, t2[19])
      ROUND512(cs, t2[20])
      ROUND512(cs, t2[21])
      ROUND512(cs, t2[22])
      ROUND512(cs, t2[23])
      ROUND512(cs, t2[24])
      ROUND512(cs, t2[25])
      ROUND512(cs, t2[26])
      ROUND512(cs, t2[27])
      ROUND512(cs, t2[28])
      ROUND512(cs, t2[29])
      ROUND512(cs, t2[30])
      ROUND512(cs, t2[31])
      ROUND512(cs, t2[32])
      ROUND512(cs, t2[33])
      ROUND512(cs, t2[34])
      ROUND512(cs, t2[35])
      ROUND512(cs, t2[36])
      ROUND512(cs, t2[37])
      ROUND512(cs, t2[38])
      ROUND512(cs, t2[39])
      ROUND512(cs, t2[40])
      ROUND512(cs, t2[41])
      ROUND512(cs, t2[42])
      ROUND512(cs, t2[43])
      ROUND512(cs, t2[44])
      ROUND512(cs, t2[45])
      ROUND512(cs, t2[46])
      ROUND512(cs, t2[47])
      ROUND512(cs, t2[48])
      ROUND512(cs, t2[49])
      ROUND512(cs, t2[50])
      ROUND512(cs, t2[51])
      ROUND512(cs, t2[52])
      ROUND512(cs, t2[53])
      ROUND512(cs, t2[54])
      ROUND512(cs, t2[55])
      ROUND512(cs, t2[56])
      ROUND512(cs, t2[57])
      ROUND512(cs, t2[58])
      ROUND512(cs, t2[59])
      ROUND512(cs, t2[60])
      ROUND512(cs, t2[61])
      ROUND512(cs, t2[62])
      ROUND512(cs, t2[63])
      ROUND512(cs, t2[64])
      ROUND512(cs, t2[65])
      ROUND512(cs, t2[66])
      ROUND512(cs, t2[67])
      ROUND512(cs, t2[68])
      ROUND512(cs, t2[69])
      ROUND512(cs, t2[70])
      ROUND512(cs, t2[71])
      ROUND512(cs, t2[72])
      ROUND512(cs, t2[73])
      ROUND512(cs, t2[74])
      ROUND512(cs, t2[75])
      ROUND512(cs, t2[76])
      ROUND512(cs, t2[77])
      ROUND512(cs, t2[78])
      ROUND512(cs, t2[79])

      state[0] += cs[0]; state[1] += cs[1]; state[2] += cs[2]; state[3] += cs[3]
      state[4] += cs[4]; state[5] += cs[5]; state[6] += cs[6]; state[7] += cs[7]

      offset += (2 * sha512.sizeBlock())
      dec(blocksCount, 2)
