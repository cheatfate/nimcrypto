#
#
#                    NimCrypto
#       (c) Copyright 2024-2025 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module is optimized SHA2-256 (Secure Hash Algorithm 2) implementation
## for AARCH64 (ARM64) using CPU SHA extension.
##
## This implementation is Nim version of C code by Nir Drucker and Shay Gueron
## (AWS Cryptographic Algorithms Group. (ndrucker@amazon.com,
## gueron@amazon.com)).
## https://github.com/aws-samples/sha2-with-c-intrinsic/blob/master/src/sha256_compress_aarch64_sha_ext.c

{.push raises: [].}
{.used.}

when defined(arm64):
  import "."/sha2_common

  {.localPassc: "-march=armv8-a+crypto".}
  {.pragma: arm64type, bycopy, header:"<arm_neon.h>".}
  {.pragma: arm64proc, nodecl, header:"<arm_neon.h>".}

  const
    SHA2_NEON_sha256Compress* = true

  type
    uint8x16* {.importc: "uint8x16_t", arm64type.} = object
      data: array[16, byte]
    uint32x4* {.importc: "uint32x4_t", arm64type.} = object
      data: array[4, uint32]
    uint8x16x4* {.importc: "uint8x16x4_t", arm64type.} = object
      data {.importc: "val".}: array[4, uint8x16]
    uint32x4x2* {.importc: "uint32x4x2_t", arm64type.} = object
      data {.importc: "val".}: array[2, uint32x4]

  proc vld1q_u8_x4(a: ptr byte): uint8x16x4 {.
       importc: "vld1q_u8_x4", arm64proc.}
  proc vst1q_u32_x2(a: ptr uint32, val: uint32x4x2) {.
       importc: "vst1q_u32_x2", arm64proc.}
  proc vreinterpretq_u32_u8(a: uint8x16): uint32x4 {.
       importc: "vreinterpretq_u32_u8", arm64proc.}
  proc vrev32q_u8(a: uint8x16): uint8x16 {.
       importc: "vrev32q_u8", arm64proc.}
  proc vld1q_u32_x2(a: ptr uint32): uint32x4x2 {.
       importc: "vld1q_u32_x2", arm64proc.}
  proc vaddq_u32(a, b: uint32x4): uint32x4 {.
       importc: "vaddq_u32", arm64proc.}
  proc vld1q_u32(a: ptr uint32): uint32x4 {.
       importc: "vld1q_u32", arm64proc.}
  proc vsha256hq_u32(abcd: uint32x4, efgh: uint32x4, wk: uint32x4): uint32x4 {.
       importc: "vsha256hq_u32", arm64proc.}
  proc vsha256h2q_u32(efgh: uint32x4, abcd: uint32x4, wk: uint32x4): uint32x4 {.
       importc: "vsha256h2q_u32", arm64proc.}
  proc vsha256su0q_u32(a, b: uint32x4): uint32x4 {.
       importc: "vsha256su0q_u32", arm64proc.}
  proc vsha256su1q_u32(tw0, w8, w12: uint32x4): uint32x4 {.
       importc: "vsha256su1q_u32", arm64proc.}

  let K0D = K0

  template load(t: typedesc[uint32x4], data: openArray[uint32],
                index: int): uint32x4 =
    vld1q_u32(cast[ptr uint32](unsafeAddr data[index]))

  template load(t: typedesc[uint32x4x2], data: openArray[uint32],
                index: int): uint32x4x2 =
    vld1q_u32_x2(cast[ptr uint32](unsafeAddr data[index]))

  template load(t: typedesc[uint8x16x4], data: openArray[byte],
                index: int): uint8x16x4 =
    vld1q_u8_x4(cast[ptr byte](unsafeAddr data[index]))

  template save(t: typedesc[uint32x4x2], data: openArray[uint32], index: int,
                value: uint32x4x2) =
    vst1q_u32_x2(cast [ptr uint32](unsafeAddr data[index]), value)

  proc sha256Compress*(state: var array[8, uint32],
                       data: openArray[byte],
                       blocks: int) {.noinit.} =
    var
      ms {.align(32), noinit.}: array[4, uint32x4]
      temp {.align(32), noinit.}: array[3, uint32x4]
      cs {.align(32).} = uint32x4x2.load(state, 0)
      offset = 0

    for j in 0 ..< blocks:
      var save = cs
      let d = uint8x16x4.load(data, offset)
      ms[0] = vreinterpretq_u32_u8(vrev32q_u8(d.data[0]))
      ms[1] = vreinterpretq_u32_u8(vrev32q_u8(d.data[1]))
      ms[2] = vreinterpretq_u32_u8(vrev32q_u8(d.data[2]))
      ms[3] = vreinterpretq_u32_u8(vrev32q_u8(d.data[3]))

      temp[0] = vaddq_u32(ms[0], uint32x4.load(K0D, 0))

      # 1
      ms[0] = vsha256su0q_u32(ms[0], ms[1])
      temp[2] = cs.data[0]
      temp[1] = vaddq_u32(ms[1], uint32x4.load(K0D, 4))
      cs.data[0] = vsha256hq_u32(cs.data[0], cs.data[1], temp[0])
      cs.data[1] = vsha256h2q_u32(cs.data[1], temp[2], temp[0])
      ms[0] = vsha256su1q_u32(ms[0], ms[2], ms[3])

      block:
        let t = ms[0]; ms[0] = ms[1]; ms[1] = ms[2]; ms[2] = ms[3]; ms[3] = t
      block:
        let t = temp[0]; temp[0] = temp[1]; temp[1] = t

      # 2
      ms[0] = vsha256su0q_u32(ms[0], ms[1])
      temp[2] = cs.data[0]
      temp[1] = vaddq_u32(ms[1], uint32x4.load(K0D, 8))
      cs.data[0] = vsha256hq_u32(cs.data[0], cs.data[1], temp[0])
      cs.data[1] = vsha256h2q_u32(cs.data[1], temp[2], temp[0])
      ms[0] = vsha256su1q_u32(ms[0], ms[2], ms[3])

      block:
        let t = ms[0]; ms[0] = ms[1]; ms[1] = ms[2]; ms[2] = ms[3]; ms[3] = t
      block:
        let t = temp[0]; temp[0] = temp[1]; temp[1] = t

      # 3
      ms[0] = vsha256su0q_u32(ms[0], ms[1])
      temp[2] = cs.data[0]
      temp[1] = vaddq_u32(ms[1], uint32x4.load(K0D, 12))
      cs.data[0] = vsha256hq_u32(cs.data[0], cs.data[1], temp[0])
      cs.data[1] = vsha256h2q_u32(cs.data[1], temp[2], temp[0])
      ms[0] = vsha256su1q_u32(ms[0], ms[2], ms[3])

      block:
        let t = ms[0]; ms[0] = ms[1]; ms[1] = ms[2]; ms[2] = ms[3]; ms[3] = t
      block:
        let t = temp[0]; temp[0] = temp[1]; temp[1] = t

      # 4
      ms[0] = vsha256su0q_u32(ms[0], ms[1])
      temp[2] = cs.data[0]
      temp[1] = vaddq_u32(ms[1], uint32x4.load(K0D, 16))
      cs.data[0] = vsha256hq_u32(cs.data[0], cs.data[1], temp[0])
      cs.data[1] = vsha256h2q_u32(cs.data[1], temp[2], temp[0])
      ms[0] = vsha256su1q_u32(ms[0], ms[2], ms[3])

      block:
        let t = ms[0]; ms[0] = ms[1]; ms[1] = ms[2]; ms[2] = ms[3]; ms[3] = t
      block:
        let t = temp[0]; temp[0] = temp[1]; temp[1] = t

      # 5
      ms[0] = vsha256su0q_u32(ms[0], ms[1])
      temp[2] = cs.data[0]
      temp[1] = vaddq_u32(ms[1], uint32x4.load(K0D, 20))
      cs.data[0] = vsha256hq_u32(cs.data[0], cs.data[1], temp[0])
      cs.data[1] = vsha256h2q_u32(cs.data[1], temp[2], temp[0])
      ms[0] = vsha256su1q_u32(ms[0], ms[2], ms[3])

      block:
        let t = ms[0]; ms[0] = ms[1]; ms[1] = ms[2]; ms[2] = ms[3]; ms[3] = t
      block:
        let t = temp[0]; temp[0] = temp[1]; temp[1] = t

      # 6
      ms[0] = vsha256su0q_u32(ms[0], ms[1])
      temp[2] = cs.data[0]
      temp[1] = vaddq_u32(ms[1], uint32x4.load(K0D, 24))
      cs.data[0] = vsha256hq_u32(cs.data[0], cs.data[1], temp[0])
      cs.data[1] = vsha256h2q_u32(cs.data[1], temp[2], temp[0])
      ms[0] = vsha256su1q_u32(ms[0], ms[2], ms[3])

      block:
        let t = ms[0]; ms[0] = ms[1]; ms[1] = ms[2]; ms[2] = ms[3]; ms[3] = t
      block:
        let t = temp[0]; temp[0] = temp[1]; temp[1] = t

      # 7
      ms[0] = vsha256su0q_u32(ms[0], ms[1])
      temp[2] = cs.data[0]
      temp[1] = vaddq_u32(ms[1], uint32x4.load(K0D, 28))
      cs.data[0] = vsha256hq_u32(cs.data[0], cs.data[1], temp[0])
      cs.data[1] = vsha256h2q_u32(cs.data[1], temp[2], temp[0])
      ms[0] = vsha256su1q_u32(ms[0], ms[2], ms[3])

      block:
        let t = ms[0]; ms[0] = ms[1]; ms[1] = ms[2]; ms[2] = ms[3]; ms[3] = t
      block:
        let t = temp[0]; temp[0] = temp[1]; temp[1] = t

      # 8
      ms[0] = vsha256su0q_u32(ms[0], ms[1])
      temp[2] = cs.data[0]
      temp[1] = vaddq_u32(ms[1], uint32x4.load(K0D, 32))
      cs.data[0] = vsha256hq_u32(cs.data[0], cs.data[1], temp[0])
      cs.data[1] = vsha256h2q_u32(cs.data[1], temp[2], temp[0])
      ms[0] = vsha256su1q_u32(ms[0], ms[2], ms[3])

      block:
        let t = ms[0]; ms[0] = ms[1]; ms[1] = ms[2]; ms[2] = ms[3]; ms[3] = t
      block:
        let t = temp[0]; temp[0] = temp[1]; temp[1] = t

      # 9
      ms[0] = vsha256su0q_u32(ms[0], ms[1])
      temp[2] = cs.data[0]
      temp[1] = vaddq_u32(ms[1], uint32x4.load(K0D, 36))
      cs.data[0] = vsha256hq_u32(cs.data[0], cs.data[1], temp[0])
      cs.data[1] = vsha256h2q_u32(cs.data[1], temp[2], temp[0])
      ms[0] = vsha256su1q_u32(ms[0], ms[2], ms[3])

      block:
        let t = ms[0]; ms[0] = ms[1]; ms[1] = ms[2]; ms[2] = ms[3]; ms[3] = t
      block:
        let t = temp[0]; temp[0] = temp[1]; temp[1] = t

      # 10
      ms[0] = vsha256su0q_u32(ms[0], ms[1])
      temp[2] = cs.data[0]
      temp[1] = vaddq_u32(ms[1], uint32x4.load(K0D, 40))
      cs.data[0] = vsha256hq_u32(cs.data[0], cs.data[1], temp[0])
      cs.data[1] = vsha256h2q_u32(cs.data[1], temp[2], temp[0])
      ms[0] = vsha256su1q_u32(ms[0], ms[2], ms[3])

      block:
        let t = ms[0]; ms[0] = ms[1]; ms[1] = ms[2]; ms[2] = ms[3]; ms[3] = t
      block:
        let t = temp[0]; temp[0] = temp[1]; temp[1] = t

      # 11
      ms[0] = vsha256su0q_u32(ms[0], ms[1])
      temp[2] = cs.data[0]
      temp[1] = vaddq_u32(ms[1], uint32x4.load(K0D, 44))
      cs.data[0] = vsha256hq_u32(cs.data[0], cs.data[1], temp[0])
      cs.data[1] = vsha256h2q_u32(cs.data[1], temp[2], temp[0])
      ms[0] = vsha256su1q_u32(ms[0], ms[2], ms[3])

      block:
        let t = ms[0]; ms[0] = ms[1]; ms[1] = ms[2]; ms[2] = ms[3]; ms[3] = t
      block:
        let t = temp[0]; temp[0] = temp[1]; temp[1] = t

      # 12
      ms[0] = vsha256su0q_u32(ms[0], ms[1])
      temp[2] = cs.data[0]
      temp[1] = vaddq_u32(ms[1], uint32x4.load(K0D, 48))
      cs.data[0] = vsha256hq_u32(cs.data[0], cs.data[1], temp[0])
      cs.data[1] = vsha256h2q_u32(cs.data[1], temp[2], temp[0])
      ms[0] = vsha256su1q_u32(ms[0], ms[2], ms[3])

      block:
        let t = ms[0]; ms[0] = ms[1]; ms[1] = ms[2]; ms[2] = ms[3]; ms[3] = t
      block:
        let t = temp[0]; temp[0] = temp[1]; temp[1] = t

      temp[2] = cs.data[0]
      temp[1] = vaddq_u32(ms[1], uint32x4.load(K0D, 52))
      cs.data[0] = vsha256hq_u32(cs.data[0], cs.data[1], temp[0])
      cs.data[1] = vsha256h2q_u32(cs.data[1], temp[2], temp[0])

      temp[2] = cs.data[0]
      temp[0] = vaddq_u32(ms[2], uint32x4.load(K0D, 56))
      cs.data[0] = vsha256hq_u32(cs.data[0], cs.data[1], temp[1])
      cs.data[1] = vsha256h2q_u32(cs.data[1], temp[2], temp[1])

      temp[2] = cs.data[0]
      temp[1] = vaddq_u32(ms[3], uint32x4.load(K0D, 60))
      cs.data[0] = vsha256hq_u32(cs.data[0], cs.data[1], temp[0])
      cs.data[1] = vsha256h2q_u32(cs.data[1], temp[2], temp[0])

      temp[2] = cs.data[0]
      cs.data[0] = vsha256hq_u32(cs.data[0], cs.data[1], temp[1])
      cs.data[1] = vsha256h2q_u32(cs.data[1], temp[2], temp[1])

      cs.data[0] = vaddq_u32(cs.data[0], save.data[0])
      cs.data[1] = vaddq_u32(cs.data[1], save.data[1])

      offset += sha256.sizeBlock()

    uint32x4x2.save(state, 0, cs)
