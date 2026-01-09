#
#
#                    NimCrypto
#       (c) Copyright 2018-2026 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements SHA3 (Secure Hash Algorithm 3) set of cryptographic
## hash functions designed by Guido Bertoni, Joan Daemen, Michaël Peeters and
## Gilles Van Assche.
##
## This module supports SHA3-224/256/384/512 and SHAKE-128/256.
##
## Tests for SHA3-224/256/384/512 made according to
## [https://www.di-mgt.com.au/sha_testvectors.html].
## Test for SHAKE-128/256 made according to
## [https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values#aHashing]
## 0bit and 1600bit test vectors used.

{.push raises: [].}
{.used.}

import ".."/[hash, utils, cpufeatures]
import "."/[keccak_common, keccak_ref, keccak_avx]
export hash
export KeccakContext, KeccakImplementation, sizeDigest, sizeBlock, name,
       keccak224, keccak256, keccak384, keccak512, sha3_224, sha3_256, sha3_384,
       sha3_512, shake128, shake256, keccak, sha3,
       cpufeatures, isAvailable, hmacSizeBlock

func reset*(ctx: var KeccakContext) {.noinit.} =
  ctx = type(ctx)()

func clear*(ctx: var KeccakContext) {.inline.} =
  when nimvm:
    for i in 0 ..< len(ctx.state):
      ctx.state[i] = 0x00'u8
      if i < len(ctx.buffer):
        ctx.buffer[i] = 0x00'u8
    ctx.pt = 0
  else:
    burnMem(ctx)

func getCompressFunction(
    KeccakContextType: typedesc[keccak|sha3|shake128|shake256],
    implementation: KeccakImplementation,
    cpufeatures: set[CpuFeature]
): KeccakCompressFunc =
  var ctx: KeccakContextType
  case ctx.getImplementation(implementation, cpufeatures)
  of KeccakModule.Ref:
    keccak_ref.keccakCompress
  of KeccakModule.Avx:
    when compiles(KECCAK_AVX_compress):
      keccak_avx.keccakCompress
    else:
      keccak_ref.keccakCompress
  of KeccakModule.Avx2:
    when compiles(KECCAK_AVX2_compress):
      keccak_avx2.keccakCompress
    else:
      when compiles(KECCAK_AVX_compress):
        keccak_avx.keccakCompress
      else:
        keccak_ref.keccakCompress

func init*(
    ctx: var KeccakContext,
    implementation: KeccakImplementation,
    cpufeatures: set[CpuFeature]
) {.noinit.} =
  ctx.compressFunc =
    getCompressFunction(type(ctx), implementation, cpufeatures)
  ctx.reset()

func init*(
    ctx: var KeccakContext,
    implementation: KeccakImplementation
) {.noinit.} =
  ctx.compressFunc =
    getCompressFunction(type(ctx), implementation, defaultCpuFeatures)
  ctx.reset()

func init*(ctx: var KeccakContext) {.noinit.} =
  ctx.compressFunc =
    when ctx is keccak224:
      when nimvm:
        keccak_ref.keccakCompress
      else:
        {.noSideEffect.}: default_keccak224_compress_func
    elif ctx is keccak256:
      when nimvm:
        keccak_ref.keccakCompress
      else:
        {.noSideEffect.}: default_keccak256_compress_func
    elif ctx is keccak384:
      when nimvm:
        keccak_ref.keccakCompress
      else:
        {.noSideEffect.}: default_keccak384_compress_func
    elif ctx is keccak512:
      when nimvm:
        keccak_ref.keccakCompress
      else:
        {.noSideEffect.}: default_keccak512_compress_func
    elif ctx is sha3_224:
      when nimvm:
        keccak_ref.keccakCompress
      else:
        {.noSideEffect.}: default_sha3224_compress_func
    elif ctx is sha3_256:
      when nimvm:
        keccak_ref.keccakCompress
      else:
        {.noSideEffect.}: default_sha3256_compress_func
    elif ctx is sha3_384:
      when nimvm:
        keccak_ref.keccakCompress
      else:
        {.noSideEffect.}: default_sha3384_compress_func
    elif ctx is sha3_512:
      when nimvm:
        keccak_ref.keccakCompress
      else:
        {.noSideEffect.}: default_sha3512_compress_func
    elif ctx is shake128:
      when nimvm:
        keccak_ref.keccakCompress
      else:
        {.noSideEffect.}: default_shake128_compress_func
    elif ctx is shake256:
      when nimvm:
        keccak_ref.keccakCompress
      else:
        {.noSideEffect.}: default_shake256_compress_func
  ctx.reset()

func update*[T: bchar](
    ctx: var KeccakContext,
    data: openArray[T]
) {.noinit.} =
  if len(data) > 0:
    let rsize = ctx.rsize()
    var
      offset = 0
      j = ctx.pt

    while offset < len(data):
      let chunk = min(rsize - j, len(data) - offset)
      copyMem(data.buffer, j, data, offset, chunk)
      j = j + chunk
      offset = offset + chunk
      if j >= rsize:
        when T is byte:
          {.noSideEffect.}:
            ctx.compressFunc(ctx.state, ctx.buffer, rsize)
        else:
          {.noSideEffect.}:
            ctx.compressFunc(
              ctx.state, ctx.buffer.toOpenArrayByte(0, rsize - 1), rsize)
        j = 0
    ctx.pt = j

func update*(
    ctx: var KeccakContext,
    pbytes: ptr byte,
    nbytes: uint
) {.noinit.} =
  if not(isNil(pbytes)) and (nbytes > 0'u):
    let p = cast[ptr UncheckedArray[byte]](pbytes)
    ctx.update(toOpenArray(p, 0, int(nbytes) - 1))

func finish*(
    ctx: var KeccakContext,
    data: var openArray[byte]
): uint {.noinit, discardable.} =
  let
    delimeter =
      when ctx.kind == KeccakKind.Sha3:
        0x06'u8
      else:
        0x01'u8
    rsize = ctx.rsize
  ctx.buffer[ctx.pt] = delimeter
  zeroMem(ctx.buffer, ctx.pt + 1, (rsize - ctx.pt - 1))
  ctx.buffer[rsize - 1] = ctx.buffer[rsize - 1] or 0x80'u8
  {.noSideEffect.}:
    ctx.compressFunc(ctx.state, ctx.buffer, rsize)
  if len(data) >= int(ctx.sizeDigest):
    for i in 0 ..< int(ctx.sizeDigest):
      data[i] = ctx.q[i]
    ctx.sizeDigest
  else:
    0

func finish*(
    ctx: var KeccakContext,
    pbytes: ptr byte,
    nbytes: uint
): uint {.noinit.} =
  let ptrarr = cast[ptr UncheckedArray[byte]](pbytes)
  ctx.finish(ptrarr.toOpenArray(0, int(nbytes) - 1))

func finish*(ctx: var KeccakContext): MDigest[ctx.bits] {.noinit.} =
  discard finish(ctx, result.data)

func xof*(ctx: var shake) {.inline.} =
  let rsize = ctx.rsize
  ctx.q[ctx.pt] = 0x1F'u8
  zeroMem(ctx.buffer, ctx.pt + 1, (rsize - ctx.pt - 1))
  ctx.q[rsize - 1] = ctx.q[rsize - 1] or 0x80'u8
  {.noSideEffect.}:
    ctx.compressFunc(ctx.state, ctx.buffer. rsize)
  ctx.pt = 0

func output*(
    ctx: var shake,
    data: var openArray[byte]
): uint {.inline.} =
  let rsize = ctx.rsize
  var j = ctx.pt
  if len(data) > 0:
    for i in 0 ..< len(data):
      if j >= ctx.rsize:
        {.noSideEffect.}:
          ctx.compressFunc(ctx.state, ctx.buffer, rsize)
        j = 0
      data[i] = ctx.q[j]
      inc(j)
    ctx.pt = j
    result = uint(len(data))

func output*(
    ctx: var shake,
    pbytes: ptr byte,
    nbytes: uint
): uint {.inline.} =
  var ptrarr = cast[ptr UncheckedArray[byte]](pbytes)
  ctx.output(ptrarr.toOpenArray(0, int(nbytes) - 1))

template declareDigest(DigestType: untyped) =
  var `default _ DigestType _ compress _ func`* {.inject.}: KeccakCompressFunc
  `default _ DigestType _ compress _ func` =
    proc(
        state: var openArray[byte],
        data: openArray[byte],
        rsize: int
    ) {.noinit, nimcall.} =
      `default _ DigestType _ compress _ func` =
        getCompressFunction(DigestType, KeccakImplementation.Auto,
          nimcryptoCpuFeatures)
      `default _ DigestType _ compress _ func`(state, data, rsize)

  func digest*[B: bchar](
      HashType: typedesc[DigestType],
      data: openArray[B],
      implementation: KeccakImplementation,
      cpufeatures: set[CpuFeature]
  ): MDigest[HashType.bits] =
    var ctx: HashType
    ctx.init(implementation, cpufeatures)
    ctx.update(data)
    let res = ctx.finish()
    ctx.clear()
    res

  func digest*[B: bchar](
      HashType: typedesc[DigestType],
      data: openArray[B],
      implementation: KeccakImplementation,
  ): MDigest[HashType.bits] =
    digest(HashType, data, implementation, defaultCpuFeatures)

  func digest*[B: bchar](
      HashType: typedesc[DigestType],
      data: openArray[B],
  ): MDigest[HashType.bits] =
    digest(HashType, data, KeccakImplementation.Auto, defaultCpuFeatures)

  func digest*(
      HashType: typedesc[DigestType],
      data: ptr byte,
      ulen: uint,
      implementation: KeccakImplementation,
      cpufeatures: set[CpuFeature]
  ): MDigest[HashType.bits] =
    var ctx: HashType
    ctx.init(implementation, cpufeatures)
    ctx.update(data, ulen)
    let res = ctx.finish()
    ctx.clear()
    res

  func digest*(
      HashType: typedesc[DigestType],
      data: ptr byte,
      ulen: uint,
      implementation: KeccakImplementation
  ): MDigest[HashType.bits] =
    digest(HashType, data, ulen, implementation, defaultCpuFeatures)

  func digest*(
      HashType: typedesc[DigestType],
      data: ptr byte,
      ulen: uint
  ): MDigest[HashType.bits] =
    digest(HashType, data, ulen, KeccakImplementation.Auto, defaultCpuFeatures)

declareDigest(keccak224)
declareDigest(keccak256)
declareDigest(keccak384)
declareDigest(keccak512)
declareDigest(sha3224)
declareDigest(sha3256)
declareDigest(sha3384)
declareDigest(sha3512)
declareDigest(shake128)
declareDigest(shake256)
