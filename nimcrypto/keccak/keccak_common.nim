#
#
#                    NimCrypto
#        (c) Copyright 2016-2025 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

{.push raises: [].}

import ".."/[hash, cpufeatures]
export hash

type
  KeccakModule* {.pure.} = enum
    Ref,
    Avx,
    Avx2

  KeccakKind* {.pure.} = enum
    Sha3, Keccak, Shake

  KeccakCompressFunc* = proc(
    state: var openArray[byte],
    data: openArray[byte],
    rsize: int
  ) {.raises: [], gcsafe, nimcall.}

  KeccakContext*[bits: static[int],
                 kind: static[KeccakKind]] = object
    buffer* {.align(32).}: array[168, byte]
    state* {.align(32).}: array[320, byte]
    pt: int
    compressFunc*: KeccakCompressFunc

  keccak224* = KeccakContext[224, Keccak]
  keccak256* = KeccakContext[256, Keccak]
  keccak384* = KeccakContext[384, Keccak]
  keccak512* = KeccakContext[512, Keccak]
  sha3_224* = KeccakContext[224, Sha3]
  sha3_256* = KeccakContext[256, Sha3]
  sha3_384* = KeccakContext[384, Sha3]
  sha3_512* = KeccakContext[512, Sha3]
  shake128* = KeccakContext[128, Shake]
  shake256* = KeccakContext[256, Shake]
  keccak* = keccak224 | keccak256 | keccak384 | keccak512
  sha3* = sha3_224 | sha3_256 | sha3_384 | sha3_512
  shake* = shake128 | shake256

  KeccakImplementation* {.pure.} = enum
    Ref,    # Reference implementation
    Avx,    # Intel AVX optimized implementation
    Avx2,   # Intel AVX2 optimized implementation
    Auto    # Generic most performant implementation

template sizeDigest*(ctx: KeccakContext): uint =
  (ctx.bits div 8)

template sizeBlock*(ctx: KeccakContext): uint =
  (200)

template rsize*(ctx: KeccakContext): int =
  200 - 2 * (ctx.bits div 8)

template sizeDigest*(r: typedesc[keccak | shake128 | shake256]): int =
  when r is shake128:
    (16)
  elif r is keccak224 or r is sha3_224:
    (28)
  elif r is keccak256 or r is sha3_256 or r is shake256:
    (32)
  elif r is keccak384 or r is sha3_384:
    (48)
  elif r is keccak512 or r is sha3_512:
    (64)

template sizeBlock*(r: typedesc[keccak | shake128 | shake256]): int =
  (200)

template hmacSizeBlock*(r: typedesc[keccak]): int =
  ## Size of processing block in octets (bytes), while perform HMAC[keccak]
  ## operation.
  when r.bits == 224:
    144
  elif r.bits == 256:
    136
  elif r.bits == 384:
    104
  elif r.bits == 512:
    72
  else:
    {.fatal: "Choosen hash primitive is not supported!".}

func name*(ctx: KeccakContext): string =
  when ctx is keccak224:
    "KECCAK-224"
  elif ctx is keccak256:
    "KECCAK-256"
  elif ctx is keccak384:
    "KECCAK-384"
  elif ctx is keccak512:
    "KECCAK-512"
  elif ctx is sha3_224:
    "SHA3-224"
  elif ctx is sha3_256:
    "SHA3-256"
  elif ctx is sha3_384:
    "SHA3-384"
  elif ctx is sha3_512:
    "SHA3-512"
  elif ctx is shake128:
    "SHAKE-128"
  elif ctx is shake256:
    "SHAKE-256"
  else:
    raiseAssert "Unknown context"

func name*(r: typedesc[keccak]): string =
  when r is keccak224:
    "KECCAK-224"
  elif r is keccak256:
    "KECCAK-256"
  elif r is keccak384:
    "KECCAK-384"
  elif r is keccak512:
    "KECCAK-512"
  elif r is sha3_224:
    "SHA3-224"
  elif r is sha3_256:
    "SHA3-256"
  elif r is sha3_384:
    "SHA3-384"
  elif r is sha3_512:
    "SHA3-512"
  elif r is shake128:
    "SHAKE-128"
  elif r is shake256:
    "SHAKE-256"
  else:
    raiseAssert "Unknown context"

func getImplementation*(
    ctx: KeccakContext,
    implementation: KeccakImplementation,
    features: set[CpuFeature]
): KeccakModule =
  when nimvm:
    # Nim's internal VM use reference implementation only.
    KeccakModule.Ref
  else:
    when defined(amd64):
      case implementation
      of KeccakImplementation.Auto:
        if CpuFeature.AVX2 in features:
          return KeccakModule.Avx2
        if CpuFeature.AVX in features:
          return KeccakModule.Avx
        KeccakModule.Ref
      of KeccakImplementation.Ref:
        KeccakModule.Ref
      of KeccakImplementation.Avx:
        if CpuFeature.AVX in features:
          KeccakModule.Avx
        else:
          raiseAssert "AVX implementation is not available on [x86_64] platform"
      of KeccakImplementation.Avx2:
        if CpuFeature.AVX2 in features:
          KeccakModule.Avx2
        else:
          raiseAssert "AVX2 implementation is not available on [x86_64] platform"
    elif defined(arm64):
      case implementation
      of KeccakImplementation.Auto:
        KeccakModule.Ref
      of KeccakImplementation.Ref:
        KeccakModule.Ref
      of KeccakImplementation.Avx:
        raiseAssert "AVX implementation is not available on [aarch64] " &
                    "platform"
      of KeccakImplementation.Avx2:
        raiseAssert "AVX2 implementation is not available on [aarch64] " &
                    "platform"
      of KeccakImplementation.ShaExt:
        raiseAssert ctx.name() & " is not supported by SHA3 extensions yet " &
          "on [aarch64] platform"
    else:
      KeccakModule.Ref

func isAvailable*(
    ctx: typedesc[KeccakContext],
    implementation: KeccakImplementation,
    features: set[CpuFeature]
): bool =
  ## This function returns ``true`` if current combination of ``implementation``
  ## and CPU ``features`` are available for the specific Keccak context ``ctx``.
  when nimvm:
    case implementation
    of KeccakImplementation.Auto, KeccakImplementation.Ref:
      true
    else:
      false
  else:
    when defined(amd64):
      case implementation
      of KeccakImplementation.Auto, KeccakImplementation.Ref:
        true
      of KeccakImplementation.Avx:
        if CpuFeature.AVX in features:
          true
        else:
          false
      of KeccakImplementation.Avx2:
        if CpuFeature.AVX2 in features:
          true
        else:
          false
    elif defined(arm64):
      case implementation
      of KeccakImplementation.Auto, KeccakImplementation.Ref:
        true
      of KeccakImplementation.Avx, KeccakImplementation.Avx2:
        false
      of KeccakImplementation.ShaExt:
        false
    else:
      case implementation
      of KeccakImplementation.Auto, KeccakImplementation.Ref:
        true
      else:
        false
