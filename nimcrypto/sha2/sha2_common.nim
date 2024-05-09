#
#
#                    NimCrypto
#        (c) Copyright 2016-2024 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

{.push raises: [].}

import ".."/[hash, utils, cpufeatures]
export hash

const
  K0* = [
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

  K1* = [
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

template CH0*(x, y, z): uint32 =
  ((x) and (y)) xor (not(x) and (z))
template MAJ0*(x, y, z): uint32 =
  ((x) and (y)) xor ((x) and (z)) xor ((y) and (z))
template CH1*(x, y, z): uint64 =
  ((x) and (y)) xor (not(x) and (z))
template MAJ1*(x, y, z): uint64 =
  ((x) and (y)) xor ((x) and (z)) xor ((y) and (z))
template TAU0*(x: uint32): uint32 =
  (ROR(x, 2) xor ROR(x, 13) xor ROR(x, 22))
template TAU1*(x: uint32): uint32 =
  (ROR(x, 6) xor ROR(x, 11) xor ROR(x, 25))
template SIG0*(x): uint32 =
  ROR(x, 7) xor ROR(x, 18) xor (x shr 3)
template SIG1*(x): uint32 =
  ROR(x, 17) xor ROR(x, 19) xor (x shr 10)
template PHI0*(x): uint64 =
  ROR(x, 28) xor ROR(x, 34) xor ROR(x, 39)
template PHI1*(x): uint64 =
  ROR(x, 14) xor ROR(x, 18) xor ROR(x, 41)
template RHO0*(x): uint64 =
  ROR(x, 1) xor ROR(x, 8) xor (x shr 7)
template RHO1*(x): uint64 =
  ROR(x, 19) xor ROR(x, 61) xor (x shr 6)

type
  Sha2Module* {.pure.} = enum
    Ref,
    Avx,
    Avx2,
    ShaExt,
    Neon

  Sha2Context*[bits: static[int],
               bsize: static[int],
               T: uint32|uint64] = object
    state* {.align(32).}: array[8, T]
    buffer* {.align(32).}: array[bsize * 2, byte]
    module*: Sha2Module
    length*: uint64
    reminder*: int

  sha224* = Sha2Context[224, 64, uint32]
  sha256* = Sha2Context[256, 64, uint32]
  sha384* = Sha2Context[384, 128, uint64]
  sha512* = Sha2Context[512, 128, uint64]
  sha512_224* = Sha2Context[224, 128, uint64]
  sha512_256* = Sha2Context[256, 128, uint64]
  sha2* = sha224 | sha256 | sha384 | sha512 | sha512_224 | sha512_256

  Sha2Implementation* {.pure.} = enum
    Ref,    # Reference implementation
    Avx,    # Intel AVX optimized implementation
    Avx2,   # Intel AVX2 optimized implementation
    ShaExt, # Intel/Arm SHA extensions optimized implementation
    Auto    # Generic most performant implementation

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

func name*(ctx: Sha2Context): string {.noinit.} =
  when ctx is sha224:
    "SHA2-224"
  elif ctx is sha256:
    "SHA2-256"
  elif ctx is sha384:
    "SHA2-384"
  elif ctx is sha512:
    "SHA2-512"
  elif ctx is sha512_224:
    "SHA2-512/224"
  elif ctx is sha512_256:
    "SHA2-512/256"
  else:
    raiseAssert "Unknown context"

func name*(r: typedesc[sha2]): string {.noinit.} =
  when r is sha224:
    "SHA-224"
  elif r is sha256:
    "SHA-256"
  elif r is sha384:
    "SHA-384"
  elif r is sha512:
    "SHA2-512"
  elif r is sha512_224:
    "SHA2-512/224"
  elif r is sha512_256:
    "SHA2-512/256"
  else:
    raiseAssert "Unknown context"

func getImplementation*(ctx: Sha2Context,
                        implementation: Sha2Implementation,
                        features: set[CpuFeature]): Sha2Module =
  when defined(nimvm):
    Sha2Module.Ref
  elif defined(amd64):
    case implementation
    of Sha2Implementation.Auto:
      when ctx.bsize == sha256.sizeBlock():
        if CpuFeature.SHA2EXT in features:
          return Sha2Module.ShaExt
        if CpuFeature.AVX2 in features:
          return Sha2Module.Avx2
        if CpuFeature.AVX in features:
          return Sha2Module.Avx
        Sha2Module.Ref
      else:
        # We do not have SHA-512 implemented using SHA extensions yet.
        if CpuFeature.AVX2 in features:
          return Sha2Module.Avx2
        if CpuFeature.AVX in features:
          return Sha2Module.Avx
        Sha2Module.Ref
    of Sha2Implementation.Ref:
      Sha2Module.Ref
    of Sha2Implementation.Avx:
      if CpuFeature.AVX in features:
        Sha2Module.Avx
      else:
        raiseAssert "AVX implementation is not available on this platform"
    of Sha2Implementation.Avx2:
      if CpuFeature.AVX2 in features:
        Sha2Module.Avx2
      else:
        raiseAssert "AVX2 implementation is not available on this platform"
    of Sha2Implementation.ShaExt:
      when ctx.bsize == sha256.sizeBlock():
        if CpuFeature.SHA2EXT in features:
          Sha2Module.ShaExt
        else:
          raiseAssert "SHA extension is not available on this platform"
      else:
        raiseAssert ctx.name() & " is not supported by SHA extensions yet"
  elif defined(arm64):
    case implementation
    of Sha2Implementation.Auto:
      when ctx.bsize == sha256.sizeBlock():
        if CpuFeature.SHA2EXT in features:
          return Sha2Module.ShaExt
        Sha2Module.Ref
      else:
        # We do not have SHA-512 implemented using SHA extensions yet.
        Sha2Module.Ref
    of Sha2Implementation.Ref:
      Sha2Module.Ref
    of Sha2Implementation.Avx:
      raiseAssert "AVX implementation is not available on this platform"
    of Sha2Implementation.Avx2:
      raiseAssert "AVX2 implementation is not available on this platform"
    of Sha2Implementation.ShaExt:
      when ctx.bsize == sha256.sizeBlock():
        if CpuFeature.SHA2EXT in features:
          Sha2Module.ShaExt
        else:
          raiseAssert "SHA extension is not available in this platform"
      else:
        raiseAssert ctx.name & " is not supported by SHA extensions yet"
  else:
    Sha2Module.Ref
