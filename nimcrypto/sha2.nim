#
#
#                    NimCrypto
#        (c) Copyright 2016 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements SHA2 (Secure Hash Algorithm 2) set of cryptographic
## hash functions designed by National Security Agency, version FIPS-180-4.
## [http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf]
##
## Tests made according to official test vectors
## [http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf].
import hash, utils
export hash

{.deadCodeElim:on.}

const
  K0 = [
    0x428a2f98'u32, 0x71374491'u32, 0xb5c0fbcf'u32, 0xe9b5dba5'u32,
    0x3956c25b'u32, 0x59f111f1'u32, 0x923f82a4'u32, 0xab1c5ed5'u32,
    0xd807aa98'u32, 0x12835b01'u32, 0x243185be'u32, 0x550c7dc3'u32,
    0x72be5d74'u32, 0x80deb1fe'u32, 0x9bdc06a7'u32, 0xc19bf174'u32,
    0xe49b69c1'u32, 0xefbe4786'u32, 0x0fc19dc6'u32, 0x240ca1cc'u32,
    0x2de92c6f'u32, 0x4a7484aa'u32, 0x5cb0a9dc'u32, 0x76f988da'u32,
    0x983e5152'u32, 0xa831c66d'u32, 0xb00327c8'u32, 0xbf597fc7'u32,
    0xc6e00bf3'u32, 0xd5a79147'u32, 0x06ca6351'u32, 0x14292967'u32,
    0x27b70a85'u32, 0x2e1b2138'u32, 0x4d2c6dfc'u32, 0x53380d13'u32,
    0x650a7354'u32, 0x766a0abb'u32, 0x81c2c92e'u32, 0x92722c85'u32,
    0xa2bfe8a1'u32, 0xa81a664b'u32, 0xc24b8b70'u32, 0xc76c51a3'u32,
    0xd192e819'u32, 0xd6990624'u32, 0xf40e3585'u32, 0x106aa070'u32,
    0x19a4c116'u32, 0x1e376c08'u32, 0x2748774c'u32, 0x34b0bcb5'u32,
    0x391c0cb3'u32, 0x4ed8aa4a'u32, 0x5b9cca4f'u32, 0x682e6ff3'u32,
    0x748f82ee'u32, 0x78a5636f'u32, 0x84c87814'u32, 0x8cc70208'u32,
    0x90befffa'u32, 0xa4506ceb'u32, 0xbef9a3f7'u32, 0xc67178f2'u32
  ]

  K1 = [
    0x428a2f98d728ae22'u64, 0x7137449123ef65cd'u64, 0xb5c0fbcfec4d3b2f'u64,
    0xe9b5dba58189dbbc'u64, 0x3956c25bf348b538'u64, 0x59f111f1b605d019'u64,
    0x923f82a4af194f9b'u64, 0xab1c5ed5da6d8118'u64, 0xd807aa98a3030242'u64,
    0x12835b0145706fbe'u64, 0x243185be4ee4b28c'u64, 0x550c7dc3d5ffb4e2'u64,
    0x72be5d74f27b896f'u64, 0x80deb1fe3b1696b1'u64, 0x9bdc06a725c71235'u64,
    0xc19bf174cf692694'u64, 0xe49b69c19ef14ad2'u64, 0xefbe4786384f25e3'u64,
    0x0fc19dc68b8cd5b5'u64, 0x240ca1cc77ac9c65'u64, 0x2de92c6f592b0275'u64,
    0x4a7484aa6ea6e483'u64, 0x5cb0a9dcbd41fbd4'u64, 0x76f988da831153b5'u64,
    0x983e5152ee66dfab'u64, 0xa831c66d2db43210'u64, 0xb00327c898fb213f'u64,
    0xbf597fc7beef0ee4'u64, 0xc6e00bf33da88fc2'u64, 0xd5a79147930aa725'u64,
    0x06ca6351e003826f'u64, 0x142929670a0e6e70'u64, 0x27b70a8546d22ffc'u64,
    0x2e1b21385c26c926'u64, 0x4d2c6dfc5ac42aed'u64, 0x53380d139d95b3df'u64,
    0x650a73548baf63de'u64, 0x766a0abb3c77b2a8'u64, 0x81c2c92e47edaee6'u64,
    0x92722c851482353b'u64, 0xa2bfe8a14cf10364'u64, 0xa81a664bbc423001'u64,
    0xc24b8b70d0f89791'u64, 0xc76c51a30654be30'u64, 0xd192e819d6ef5218'u64,
    0xd69906245565a910'u64, 0xf40e35855771202a'u64, 0x106aa07032bbd1b8'u64,
    0x19a4c116b8d2d0c8'u64, 0x1e376c085141ab53'u64, 0x2748774cdf8eeb99'u64,
    0x34b0bcb5e19b48a8'u64, 0x391c0cb3c5c95a63'u64, 0x4ed8aa4ae3418acb'u64,
    0x5b9cca4f7763e373'u64, 0x682e6ff3d6b2b8a3'u64, 0x748f82ee5defb2fc'u64,
    0x78a5636f43172f60'u64, 0x84c87814a1f0ab72'u64, 0x8cc702081a6439ec'u64,
    0x90befffa23631e28'u64, 0xa4506cebde82bde9'u64, 0xbef9a3f7b2c67915'u64,
    0xc67178f2e372532b'u64, 0xca273eceea26619c'u64, 0xd186b8c721c0c207'u64,
    0xeada7dd6cde0eb1e'u64, 0xf57d4f7fee6ed178'u64, 0x06f067aa72176fba'u64,
    0x0a637dc5a2c898a6'u64, 0x113f9804bef90dae'u64, 0x1b710b35131c471b'u64,
    0x28db77f523047d84'u64, 0x32caab7b40c72493'u64, 0x3c9ebe0a15c9bebc'u64,
    0x431d67c49c100d4c'u64, 0x4cc5d4becb3e42b6'u64, 0x597f299cfc657e2a'u64,
    0x5fcb6fab3ad6faec'u64, 0x6c44198c4a475817'u64
  ]

template CH0(x, y, z): uint32 =
  ((x) and (y)) xor (not(x) and (z))
template MAJ0(x, y, z): uint32 =
  ((x) and (y)) xor ((x) and (z)) xor ((y) and (z))
template CH1(x, y, z): uint64 =
  ((x) and (y)) xor (not(x) and (z))
template MAJ1(x, y, z): uint64 =
  ((x) and (y)) xor ((x) and (z)) xor ((y) and (z))
template TAU0(x: uint32): uint32 =
  (ROR(x, 2) xor ROR(x, 13) xor ROR(x, 22))
template TAU1(x: uint32): uint32 =
  (ROR(x, 6) xor ROR(x, 11) xor ROR(x, 25))
template SIG0(x): uint32 =
  ROR(x, 7) xor ROR(x, 18) xor (x shr 3)
template SIG1(x): uint32 =
  ROR(x, 17) xor ROR(x, 19) xor (x shr 10)
template PHI0(x): uint64 =
  ROR(x, 28) xor ROR(x, 34) xor ROR(x, 39)
template PHI1(x): uint64 =
  ROR(x, 14) xor ROR(x, 18) xor ROR(x, 41)
template RHO0(x): uint64 =
  ROR(x, 1) xor ROR(x, 8) xor (x shr 7)
template RHO1(x): uint64 =
  ROR(x, 19) xor ROR(x, 61) xor (x shr 6)

type
  Sha2Context*[bits: static[int],
               bsize: static[int],
               T: uint32|uint64] = object
    count: array[2, T]
    state: array[8, T]
    buffer: array[bsize, byte]

  sha224* = Sha2Context[224, 64, uint32]
  sha256* = Sha2Context[256, 64, uint32]
  sha384* = Sha2Context[384, 128, uint64]
  sha512* = Sha2Context[512, 128, uint64]
  sha512_224* = Sha2Context[224, 128, uint64]
  sha512_256* = Sha2Context[256, 128, uint64]
  sha2* = sha224 | sha256 | sha384 | sha512 | sha512_224 | sha512_256

template sizeDigest*(ctx: Sha2Context): uint =
  (ctx.bits div 8)

template sizeBlock*(ctx: Sha2Context): uint =
  (ctx.bsize)

template sizeDigest*(r: typedesc[sha2]): int =
  when r is sha224 or r is sha512_224:
    (28)
  elif r is sha256 or r is sha512_256:
    (32)
  elif r is sha384:
    (48)
  elif r is sha512:
    (64)

template sizeBlock*(r: typedesc[sha2]): int =
  when r is sha224 or r is sha256:
    (64)
  else:
    (128)

proc init*(ctx: var Sha2Context) {.inline.} =
  ctx.count[0] = 0
  ctx.count[1] = 0
  when ctx.bits == 224 and ctx.bsize == 64:
    ctx.state[0] = 0xC1059ED8'u32
    ctx.state[1] = 0x367CD507'u32
    ctx.state[2] = 0x3070DD17'u32
    ctx.state[3] = 0xF70E5939'u32
    ctx.state[4] = 0xFFC00B31'u32
    ctx.state[5] = 0x68581511'u32
    ctx.state[6] = 0x64F98FA7'u32
    ctx.state[7] = 0xBEFA4FA4'u32
  elif ctx.bits == 256 and ctx.bsize == 64:
    ctx.state[0] = 0x6A09E667'u32
    ctx.state[1] = 0xBB67AE85'u32
    ctx.state[2] = 0x3C6EF372'u32
    ctx.state[3] = 0xA54FF53A'u32
    ctx.state[4] = 0x510E527F'u32
    ctx.state[5] = 0x9B05688C'u32
    ctx.state[6] = 0x1F83D9AB'u32
    ctx.state[7] = 0x5BE0CD19'u32
  elif ctx.bits == 384 and ctx.bsize == 128:
    ctx.state[0] = 0xCBBB9D5DC1059ED8'u64
    ctx.state[1] = 0x629A292A367CD507'u64
    ctx.state[2] = 0x9159015A3070DD17'u64
    ctx.state[3] = 0x152FECD8F70E5939'u64
    ctx.state[4] = 0x67332667FFC00B31'u64
    ctx.state[5] = 0x8EB44A8768581511'u64
    ctx.state[6] = 0xDB0C2E0D64F98FA7'u64
    ctx.state[7] = 0x47B5481DBEFA4FA4'u64
  elif ctx.bits == 512 and ctx.bsize == 128:
    ctx.state[0] = 0x6A09E667F3BCC908'u64
    ctx.state[1] = 0xBB67AE8584CAA73B'u64
    ctx.state[2] = 0x3C6EF372FE94F82B'u64
    ctx.state[3] = 0xA54FF53A5F1D36F1'u64
    ctx.state[4] = 0x510E527FADE682D1'u64
    ctx.state[5] = 0x9B05688C2B3E6C1F'u64
    ctx.state[6] = 0x1F83D9ABFB41BD6B'u64
    ctx.state[7] = 0x5BE0CD19137E2179'u64
  elif ctx.bits == 224 and ctx.bsize == 128:
    ctx.state[0] = 0x8C3D37C819544DA2'u64
    ctx.state[1] = 0x73E1996689DCD4D6'u64
    ctx.state[2] = 0x1DFAB7AE32FF9C82'u64
    ctx.state[3] = 0x679DD514582F9FCF'u64
    ctx.state[4] = 0x0F6D2B697BD44DA8'u64
    ctx.state[5] = 0x77E36F7304C48942'u64
    ctx.state[6] = 0x3F9D85A86A1D36C8'u64
    ctx.state[7] = 0x1112E6AD91D692A1'u64
  elif ctx.bits == 256 and ctx.bsize == 128:
    ctx.state[0] = 0x22312194FC2BF72C'u64
    ctx.state[1] = 0x9F555FA3C84C64C2'u64
    ctx.state[2] = 0x2393B86B6F53B151'u64
    ctx.state[3] = 0x963877195940EABD'u64
    ctx.state[4] = 0x96283EE2A88EFFE3'u64
    ctx.state[5] = 0xBE5E1E2553863992'u64
    ctx.state[6] = 0x2B0199FC2C85B8AA'u64
    ctx.state[7] = 0x0EB72DDC81C52CA2'u64

proc clear*(ctx: var Sha2Context) {.inline.} =
  when nimvm:
    when ctx.bsize == 64:
      ctx.count[0] = 0x00'u32
      ctx.count[1] = 0x00'u32
      ctx.state[0] = 0x00'u32
      ctx.state[1] = 0x00'u32
      ctx.state[2] = 0x00'u32
      ctx.state[3] = 0x00'u32
      ctx.state[4] = 0x00'u32
      ctx.state[5] = 0x00'u32
      ctx.state[6] = 0x00'u32
      ctx.state[7] = 0x00'u32
    elif ctx.bsize == 128:
      ctx.count[0] = 0x00'u64
      ctx.count[1] = 0x00'u64
      ctx.state[0] = 0x00'u64
      ctx.state[1] = 0x00'u64
      ctx.state[2] = 0x00'u64
      ctx.state[3] = 0x00'u64
      ctx.state[4] = 0x00'u64
      ctx.state[5] = 0x00'u64
      ctx.state[6] = 0x00'u64
      ctx.state[7] = 0x00'u64
    for i in 0 ..< ctx.bsize:
      ctx.buffer[i] = 0x00'u8
  else:
    burnMem(ctx)

proc reset*(ctx: var Sha2Context) {.inline.} =
  init(ctx)

template ROUND256(a, b, c, d, e, f, g, h, z) =
  t0 = h + TAU1(e) + CH0(e, f, g) + K0[z] + W[z]
  t1 = TAU0(a) + MAJ0(a, b, c)
  d = d + t0
  h = t0 + t1

template ROUND512(a, b, c, d, e, f, g, h, z) =
  t0 = h + PHI1(e) + CH1(e, f, g) + K1[z] + W[z]
  t1 = PHI0(a) + MAJ1(a, b, c)
  d = d + t0
  h = t0 + t1

proc sha256Transform(state: var array[8, uint32], data: openArray[byte]) =
  var
    t0, t1: uint32
    W {.noinit.}: array[64, uint32]

  W[0] = beLoad32(data, 0); W[1] = beLoad32(data, 4);
  W[2] = beLoad32(data, 8); W[3] = beLoad32(data, 12)
  W[4] = beLoad32(data, 16); W[5] = beLoad32(data, 20)
  W[6] = beLoad32(data, 24); W[7] = beLoad32(data, 28)
  W[8] = beLoad32(data, 32); W[9] = beLoad32(data, 36)
  W[10] = beLoad32(data, 40); W[11] = beLoad32(data, 44)
  W[12] = beLoad32(data, 48); W[13] = beLoad32(data, 52)
  W[14] = beLoad32(data, 56); W[15] = beLoad32(data, 60)

  for i in 16 ..< 64:
    W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16]

  var s0 = state[0]
  var s1 = state[1]
  var s2 = state[2]
  var s3 = state[3]
  var s4 = state[4]
  var s5 = state[5]
  var s6 = state[6]
  var s7 = state[7]

  ROUND256(s0, s1, s2, s3, s4, s5, s6, s7, 0)
  ROUND256(s7, s0, s1, s2, s3, s4, s5, s6, 1)
  ROUND256(s6, s7, s0, s1, s2, s3, s4, s5, 2)
  ROUND256(s5, s6, s7, s0, s1, s2, s3, s4, 3)
  ROUND256(s4, s5, s6, s7, s0, s1, s2, s3, 4)
  ROUND256(s3, s4, s5, s6, s7, s0, s1, s2, 5)
  ROUND256(s2, s3, s4, s5, s6, s7, s0, s1, 6)
  ROUND256(s1, s2, s3, s4, s5, s6, s7, s0, 7)
  ROUND256(s0, s1, s2, s3, s4, s5, s6, s7, 8)
  ROUND256(s7, s0, s1, s2, s3, s4, s5, s6, 9)
  ROUND256(s6, s7, s0, s1, s2, s3, s4, s5, 10)
  ROUND256(s5, s6, s7, s0, s1, s2, s3, s4, 11)
  ROUND256(s4, s5, s6, s7, s0, s1, s2, s3, 12)
  ROUND256(s3, s4, s5, s6, s7, s0, s1, s2, 13)
  ROUND256(s2, s3, s4, s5, s6, s7, s0, s1, 14)
  ROUND256(s1, s2, s3, s4, s5, s6, s7, s0, 15)

  ROUND256(s0, s1, s2, s3, s4, s5, s6, s7, 16)
  ROUND256(s7, s0, s1, s2, s3, s4, s5, s6, 17)
  ROUND256(s6, s7, s0, s1, s2, s3, s4, s5, 18)
  ROUND256(s5, s6, s7, s0, s1, s2, s3, s4, 19)
  ROUND256(s4, s5, s6, s7, s0, s1, s2, s3, 20)
  ROUND256(s3, s4, s5, s6, s7, s0, s1, s2, 21)
  ROUND256(s2, s3, s4, s5, s6, s7, s0, s1, 22)
  ROUND256(s1, s2, s3, s4, s5, s6, s7, s0, 23)
  ROUND256(s0, s1, s2, s3, s4, s5, s6, s7, 24)
  ROUND256(s7, s0, s1, s2, s3, s4, s5, s6, 25)
  ROUND256(s6, s7, s0, s1, s2, s3, s4, s5, 26)
  ROUND256(s5, s6, s7, s0, s1, s2, s3, s4, 27)
  ROUND256(s4, s5, s6, s7, s0, s1, s2, s3, 28)
  ROUND256(s3, s4, s5, s6, s7, s0, s1, s2, 29)
  ROUND256(s2, s3, s4, s5, s6, s7, s0, s1, 30)
  ROUND256(s1, s2, s3, s4, s5, s6, s7, s0, 31)

  ROUND256(s0, s1, s2, s3, s4, s5, s6, s7, 32)
  ROUND256(s7, s0, s1, s2, s3, s4, s5, s6, 33)
  ROUND256(s6, s7, s0, s1, s2, s3, s4, s5, 34)
  ROUND256(s5, s6, s7, s0, s1, s2, s3, s4, 35)
  ROUND256(s4, s5, s6, s7, s0, s1, s2, s3, 36)
  ROUND256(s3, s4, s5, s6, s7, s0, s1, s2, 37)
  ROUND256(s2, s3, s4, s5, s6, s7, s0, s1, 38)
  ROUND256(s1, s2, s3, s4, s5, s6, s7, s0, 39)
  ROUND256(s0, s1, s2, s3, s4, s5, s6, s7, 40)
  ROUND256(s7, s0, s1, s2, s3, s4, s5, s6, 41)
  ROUND256(s6, s7, s0, s1, s2, s3, s4, s5, 42)
  ROUND256(s5, s6, s7, s0, s1, s2, s3, s4, 43)
  ROUND256(s4, s5, s6, s7, s0, s1, s2, s3, 44)
  ROUND256(s3, s4, s5, s6, s7, s0, s1, s2, 45)
  ROUND256(s2, s3, s4, s5, s6, s7, s0, s1, 46)
  ROUND256(s1, s2, s3, s4, s5, s6, s7, s0, 47)

  ROUND256(s0, s1, s2, s3, s4, s5, s6, s7, 48)
  ROUND256(s7, s0, s1, s2, s3, s4, s5, s6, 49)
  ROUND256(s6, s7, s0, s1, s2, s3, s4, s5, 50)
  ROUND256(s5, s6, s7, s0, s1, s2, s3, s4, 51)
  ROUND256(s4, s5, s6, s7, s0, s1, s2, s3, 52)
  ROUND256(s3, s4, s5, s6, s7, s0, s1, s2, 53)
  ROUND256(s2, s3, s4, s5, s6, s7, s0, s1, 54)
  ROUND256(s1, s2, s3, s4, s5, s6, s7, s0, 55)
  ROUND256(s0, s1, s2, s3, s4, s5, s6, s7, 56)
  ROUND256(s7, s0, s1, s2, s3, s4, s5, s6, 57)
  ROUND256(s6, s7, s0, s1, s2, s3, s4, s5, 58)
  ROUND256(s5, s6, s7, s0, s1, s2, s3, s4, 59)
  ROUND256(s4, s5, s6, s7, s0, s1, s2, s3, 60)
  ROUND256(s3, s4, s5, s6, s7, s0, s1, s2, 61)
  ROUND256(s2, s3, s4, s5, s6, s7, s0, s1, 62)
  ROUND256(s1, s2, s3, s4, s5, s6, s7, s0, 63)

  state[0] = state[0] + s0
  state[1] = state[1] + s1
  state[2] = state[2] + s2
  state[3] = state[3] + s3
  state[4] = state[4] + s4
  state[5] = state[5] + s5
  state[6] = state[6] + s6
  state[7] = state[7] + s7

proc sha512Transform(state: var array[8, uint64], data: openArray[byte]) =
  var
    t0, t1: uint64
    W {.noinit.}: array[80, uint64]

  W[0] = beLoad64(data, 0); W[1] = beLoad64(data, 8);
  W[2] = beLoad64(data, 16); W[3] = beLoad64(data, 24)
  W[4] = beLoad64(data, 32); W[5] = beLoad64(data, 40)
  W[6] = beLoad64(data, 48); W[7] = beLoad64(data, 56)
  W[8] = beLoad64(data, 64); W[9] = beLoad64(data, 72)
  W[10] = beLoad64(data, 80); W[11] = beLoad64(data, 88)
  W[12] = beLoad64(data, 96); W[13] = beLoad64(data, 104)
  W[14] = beLoad64(data, 112); W[15] = beLoad64(data, 120)

  for i in 16 ..< 80:
    W[i] = RHO1(W[i - 2]) + W[i - 7] + RHO0(W[i - 15]) + W[i - 16]

  var s0 = state[0]
  var s1 = state[1]
  var s2 = state[2]
  var s3 = state[3]
  var s4 = state[4]
  var s5 = state[5]
  var s6 = state[6]
  var s7 = state[7]

  ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 0)
  ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 1)
  ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 2)
  ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 3)
  ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 4)
  ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 5)
  ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 6)
  ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 7)
  ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 8)
  ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 9)
  ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 10)
  ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 11)
  ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 12)
  ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 13)
  ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 14)
  ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 15)

  ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 16)
  ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 17)
  ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 18)
  ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 19)
  ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 20)
  ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 21)
  ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 22)
  ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 23)
  ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 24)
  ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 25)
  ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 26)
  ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 27)
  ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 28)
  ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 29)
  ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 30)
  ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 31)

  ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 32)
  ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 33)
  ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 34)
  ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 35)
  ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 36)
  ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 37)
  ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 38)
  ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 39)
  ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 40)
  ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 41)
  ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 42)
  ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 43)
  ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 44)
  ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 45)
  ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 46)
  ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 47)

  ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 48)
  ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 49)
  ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 50)
  ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 51)
  ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 52)
  ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 53)
  ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 54)
  ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 55)
  ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 56)
  ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 57)
  ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 58)
  ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 59)
  ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 60)
  ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 61)
  ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 62)
  ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 63)

  ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 64)
  ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 65)
  ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 66)
  ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 67)
  ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 68)
  ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 69)
  ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 70)
  ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 71)
  ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 72)
  ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 73)
  ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 74)
  ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 75)
  ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 76)
  ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 77)
  ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 78)
  ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 79)

  state[0] = state[0] + s0
  state[1] = state[1] + s1
  state[2] = state[2] + s2
  state[3] = state[3] + s3
  state[4] = state[4] + s4
  state[5] = state[5] + s5
  state[6] = state[6] + s6
  state[7] = state[7] + s7

proc update*[T: bchar](ctx: var Sha2Context, data: openArray[T]) {.inline.} =
  var pos = 0
  var length = len(data)

  when ctx.bsize == 64:
    while length > 0:
      let offset = int(ctx.count[0] and 0x3F)
      let size = min(64 - offset, length)
      copyMem(ctx.buffer, offset, data, pos, size)
      pos = pos + size
      length = length - size
      ctx.count[0] = ctx.count[0] + uint32(size)
      if ctx.count[0] < uint32(size):
        ctx.count[1] = ctx.count[1] + 1'u32
      if (ctx.count[0] and 0x3F'u32) == 0:
        sha256Transform(ctx.state, ctx.buffer)
  elif ctx.bsize == 128:
    while length > 0:
      let offset = int(ctx.count[0] and 0x7F)
      let size = min(128 - offset, length)
      copyMem(ctx.buffer, offset, data, pos, size)
      pos = pos + size
      length = length - size
      ctx.count[0] = ctx.count[0] + uint64(size)
      if ctx.count[0] < uint64(size):
        ctx.count[1] = ctx.count[1] + 1'u64
      if (ctx.count[0] and 0x7F'u64) == 0:
        sha512Transform(ctx.state, ctx.buffer)

proc update*(ctx: var Sha2Context, pbytes: ptr byte, nbytes: uint) {.inline.} =
  var p = cast[ptr UncheckedArray[byte]](pbytes)
  ctx.update(toOpenArray(p, 0, int(nbytes) - 1))

proc finalize256(ctx: var Sha2Context) {.inline.} =
  var j = int(ctx.count[0] and 0x3F'u32)
  ctx.buffer[j] = 0x80'u8
  inc(j)
  while j != 56:
    if j == 64:
      sha256Transform(ctx.state, ctx.buffer)
      j = 0
    ctx.buffer[j] = 0x00'u8
    inc(j)
  ctx.count[1] = (ctx.count[1] shl 3) + (ctx.count[0] shr 29)
  ctx.count[0] = ctx.count[0] shl 3
  beStore32(ctx.buffer, 56, ctx.count[1])
  beStore32(ctx.buffer, 60, ctx.count[0])
  sha256Transform(ctx.state, ctx.buffer)

proc finalize512(ctx: var Sha2Context) {.inline.} =
  var j = int(ctx.count[0] and 0x7F'u64)
  ctx.buffer[j] = 0x80'u8
  inc(j)
  while j != 112:
    if j == 128:
      sha512Transform(ctx.state, ctx.buffer)
      j = 0
    ctx.buffer[j] = 0x00'u8
    inc(j)
  ctx.count[1] = (ctx.count[1] shl 3) + (ctx.count[0] shr 29)
  ctx.count[0] = ctx.count[0] shl 3
  beStore64(ctx.buffer, 112, ctx.count[1])
  beStore64(ctx.buffer, 120, ctx.count[0])
  sha512Transform(ctx.state, ctx.buffer)

proc finish*(ctx: var Sha2Context,
             data: var openArray[byte]): uint {.inline, discardable.} =
  result = 0'u
  when ctx.bits == 224 and ctx.bsize == 64:
    if len(data) >= 28:
      finalize256(ctx)
      result = sizeDigest(ctx)
      beStore32(data, 0, ctx.state[0])
      beStore32(data, 4, ctx.state[1])
      beStore32(data, 8, ctx.state[2])
      beStore32(data, 12, ctx.state[3])
      beStore32(data, 16, ctx.state[4])
      beStore32(data, 20, ctx.state[5])
      beStore32(data, 24, ctx.state[6])
  elif ctx.bits == 256 and ctx.bsize == 64:
    if len(data) >= 32:
      finalize256(ctx)
      result = sizeDigest(ctx)
      beStore32(data, 0, ctx.state[0])
      beStore32(data, 4, ctx.state[1])
      beStore32(data, 8, ctx.state[2])
      beStore32(data, 12, ctx.state[3])
      beStore32(data, 16, ctx.state[4])
      beStore32(data, 20, ctx.state[5])
      beStore32(data, 24, ctx.state[6])
      beStore32(data, 28, ctx.state[7])
  elif ctx.bits == 384 and ctx.bsize == 128:
    if len(data) >= 48:
      finalize512(ctx)
      result = sizeDigest(ctx)
      beStore64(data, 0, ctx.state[0])
      beStore64(data, 8, ctx.state[1])
      beStore64(data, 16, ctx.state[2])
      beStore64(data, 24, ctx.state[3])
      beStore64(data, 32, ctx.state[4])
      beStore64(data, 40, ctx.state[5])
  elif ctx.bits == 512 and ctx.bsize == 128:
    if len(data) >= 64:
      finalize512(ctx)
      result = sizeDigest(ctx)
      beStore64(data, 0, ctx.state[0])
      beStore64(data, 8, ctx.state[1])
      beStore64(data, 16, ctx.state[2])
      beStore64(data, 24, ctx.state[3])
      beStore64(data, 32, ctx.state[4])
      beStore64(data, 40, ctx.state[5])
      beStore64(data, 48, ctx.state[6])
      beStore64(data, 56, ctx.state[7])
  elif ctx.bits == 256 and ctx.bsize == 128:
    if len(data) >= 32:
      finalize512(ctx)
      result = sizeDigest(ctx)
      beStore64(data, 0, ctx.state[0])
      beStore64(data, 8, ctx.state[1])
      beStore64(data, 16, ctx.state[2])
      beStore64(data, 24, ctx.state[3])
  elif ctx.bits == 224 and ctx.bsize == 128:
    if len(data) >= 28:
      finalize512(ctx)
      result = sizeDigest(ctx)
      beStore64(data, 0, ctx.state[0])
      beStore64(data, 8, ctx.state[1])
      beStore64(data, 16, ctx.state[2])
      beStore32(data, 24, uint32(ctx.state[3] shr 32))

proc finish*(ctx: var Sha2Context, pbytes: ptr byte,
             nbytes: uint): uint {.inline.} =
  var ptrarr = cast[ptr UncheckedArray[byte]](pbytes)
  result = ctx.finish(ptrarr.toOpenArray(0, int(nbytes) - 1))

proc finish*(ctx: var Sha2Context): MDigest[ctx.bits] =
  discard finish(ctx, result.data)
