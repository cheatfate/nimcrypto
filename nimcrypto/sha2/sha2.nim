#
#
#                    NimCrypto
#      (c) Copyright 2016-2024 Eugene Kabanov
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

{.push raises: [].}

import ".."/[hash, utils, cpufeatures]
import "."/[sha2_common, sha2_ref, sha2_avx, sha2_avx2, sha2_sha, sha2_neon]
export hash
export Sha2Context, Sha2Implementation, sizeDigest, sizeBlock, name,
       sha224, sha256, sha384, sha512, sha512_224, sha512_256, sha2,
       cpufeatures, isAvailable

proc reset*(ctx: var Sha2Context) {.noinit.} =
  ctx.length = 0'u64
  ctx.reminder = 0
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

proc init*(ctx: var Sha2Context,
           implementation = Sha2Implementation.Auto,
           cpufeatures: set[CpuFeature] = {}) {.noinit.} =
  ctx.module = ctx.getImplementation(implementation, cpufeatures)
  ctx.reset()

proc init*(ctx: var Sha2Context,
           cpufeatures: set[CpuFeature]) {.noinit.} =
  ctx.module = ctx.getImplementation(Sha2Implementation.Auto, cpufeatures)
  ctx.reset()

proc clear*(ctx: var Sha2Context) {.noinit.} =
  when nimvm:
    for i in 0 ..< len(ctx.state):
      ctx.state[i] = when ctx.bsize == 64: 0'u32 else: 0'u64
    for i in 0 ..< ctx.bsize:
      ctx.buffer[i] = 0x00'u8
  else:
    burnMem(ctx)

template compress(ctx: var Sha2Context, data: openArray[byte], blocks: int) =
  when (ctx is sha224) or (ctx is sha256):
    mixin sha256Compress
    case ctx.module
    of Sha2Module.Ref:
      sha2_ref.sha256Compress(ctx.state, data, blocks)
    of Sha2Module.Avx:
      when compiles(SHA2_AVX_sha256Compress):
        sha2_avx.sha256Compress(ctx.state, data, blocks)
      else:
        raiseAssert "AVX implementation is not available for " &
                    ctx.name()
    of Sha2Module.Avx2:
      when compiles(SHA2_AVX2_sha256Compress):
        sha2_avx2.sha256Compress(ctx.state, data, blocks)
      else:
        raiseAssert "AVX2 implementation is not available for " &
                    ctx.name()
    of Sha2Module.ShaExt:
      when compiles(SHA2_SHAEXT_sha256Compress):
        sha2_sha.sha256Compress(ctx.state, data, blocks)
      else:
        raiseAssert "SHA extensions implementation is not available for " &
                    ctx.name()
    of Sha2Module.Neon:
      when compiles(SHA2_NEON_sha256Compress):
        sha2_neon.sha256Compress(ctx.state, data, blocks)
      else:
        raiseAssert "SHA2(neon) extensions implementation is not available " &
                    "for " & ctx.name()
  elif (ctx is sha384) or (ctx is sha512) or (ctx is sha512_224) or
       (ctx is sha512_256):
    mixin sha512Compress
    case ctx.module
    of Sha2Module.Ref:
      sha2_ref.sha512Compress(ctx.state, data, blocks)
    of Sha2Module.Avx:
      when compiles(SHA2_AVX_sha512Compress):
        sha2_avx.sha512Compress(ctx.state, data, blocks)
      else:
        raiseAssert "AVX implementation is not available for " &
                    ctx.name()
    of Sha2Module.Avx2:
      when compiles(SHA2_AVX2_sha512Compress):
        sha2_avx2.sha512Compress(ctx.state, data, blocks)
      else:
        raiseAssert "AVX2 implementation is not available for " &
                    ctx.name()
    of Sha2Module.ShaExt:
      when compiles(SHA2_SHAEXT_sha512Compress):
        sha2_sha.sha512Compress(ctx.state, data, blocks)
      else:
        raiseAssert "SHA2 extensions implementation is not available for " &
                    ctx.name()
    of Sha2Module.Neon:
      when compiles(SHA2_NEON_sha512Compress):
        sha2_neon.sha512Compress(ctx.state, data, blocks)
      else:
        raiseAssert "SHA2(neon) extensions implementation is not available " &
                    "for " & ctx.name()
  else:
    raiseAssert "Invalid context"

proc update*[T: bchar](ctx: var Sha2Context, data: openArray[T]) {.noinit.} =
  var
    pos = 0
    bytesLeft = len(data)

  if bytesLeft == 0:
    return

  ctx.length += uint64(bytesLeft)

  if (ctx.reminder != 0) and
     ((uint64(ctx.reminder) + uint64(bytesLeft)) < ctx.sizeBlock()):
    copyMem(ctx.buffer, ctx.reminder, data, 0, bytesLeft)
    ctx.reminder += bytesLeft
    return

  if ctx.reminder != 0:
    let clen = int(ctx.sizeBlock()) - ctx.reminder
    copyMem(ctx.buffer, ctx.reminder, data, 0, clen)
    compress(ctx, ctx.buffer, 1)
    pos += clen
    bytesLeft -= clen
    ctx.reminder = 0
    zeroMem(ctx.buffer, 0, int(ctx.sizeBlock))

  if bytesLeft >= int(ctx.sizeBlock):
    let
      blocksCount =
        when (ctx is sha224) or (ctx is sha256):
          bytesLeft shr 6
        else:
          bytesLeft shr 7
      blocksLength =
        when (ctx is sha224) or (ctx is sha256):
          blocksCount shl 6
        else:
          blocksCount shl 7
    when T is byte:
      compress(ctx, data.toOpenArray(pos, pos + blocksLength - 1), blocksCount)
    else:
      compress(ctx, data.toOpenArrayByte(pos, pos + blocksLength - 1),
               blocksCount)
    pos += blocksLength
    bytesLeft -= blocksLength

  if bytesLeft > 0:
    copyMem(ctx.buffer, 0, data, pos, bytesLeft)
    ctx.reminder = bytesLeft

proc update*(ctx: var Sha2Context, pbytes: ptr byte, nbytes: uint) {.noinit.} =
  if not(isNil(pbytes)) and (nbytes > 0'u):
    let p = cast[ptr UncheckedArray[byte]](pbytes)
    ctx.update(toOpenArray(p, 0, int(nbytes) - 1))

proc finalize256(ctx: var Sha2Context) {.inline, noinit.} =
  let
    bLength = ctx.length shl 3
    lastBlocksCount = if (ctx.reminder < 56): 1 else: 2
    sizePos = (lastBlocksCount * int(ctx.sizeBlock())) - sizeof(uint64)

  ctx.buffer[ctx.reminder] = 0x80'u8
  inc(ctx.reminder)

  zeroMem(ctx.buffer, ctx.reminder, len(ctx.buffer) - ctx.reminder)
  beStore64(ctx.buffer, sizePos, bLength)
  compress(ctx, ctx.buffer, lastBlocksCount)

proc finalize512(ctx: var Sha2Context) {.inline, noinit.} =
  let
    bLength = ctx.length shl 3
    lastBlocksCount = if (ctx.reminder < 112): 1 else: 2
    sizePos = (lastBlocksCount * int(ctx.sizeBlock())) - sizeof(uint64)

  ctx.buffer[ctx.reminder] = 0x80'u8
  inc(ctx.reminder)

  zeroMem(ctx.buffer, ctx.reminder, len(ctx.buffer) - ctx.reminder)
  beStore64(ctx.buffer, sizePos, bLength)
  compress(ctx, ctx.buffer, lastBlocksCount)

proc finish*(ctx: var Sha2Context,
             data: var openArray[byte]): uint {.noinit, discardable.} =
  when ctx.bits == 224 and ctx.bsize == 64:
    if len(data) >= 28:
      finalize256(ctx)
      beStore32(data, 0, ctx.state[0])
      beStore32(data, 4, ctx.state[1])
      beStore32(data, 8, ctx.state[2])
      beStore32(data, 12, ctx.state[3])
      beStore32(data, 16, ctx.state[4])
      beStore32(data, 20, ctx.state[5])
      beStore32(data, 24, ctx.state[6])
      sizeDigest(ctx)
    else:
      0'u
  elif ctx.bits == 256 and ctx.bsize == 64:
    if len(data) >= 32:
      finalize256(ctx)
      beStore32(data, 0, ctx.state[0])
      beStore32(data, 4, ctx.state[1])
      beStore32(data, 8, ctx.state[2])
      beStore32(data, 12, ctx.state[3])
      beStore32(data, 16, ctx.state[4])
      beStore32(data, 20, ctx.state[5])
      beStore32(data, 24, ctx.state[6])
      beStore32(data, 28, ctx.state[7])
      sizeDigest(ctx)
    else:
      0'u
  elif ctx.bits == 384 and ctx.bsize == 128:
    if len(data) >= 48:
      finalize512(ctx)
      beStore64(data, 0, ctx.state[0])
      beStore64(data, 8, ctx.state[1])
      beStore64(data, 16, ctx.state[2])
      beStore64(data, 24, ctx.state[3])
      beStore64(data, 32, ctx.state[4])
      beStore64(data, 40, ctx.state[5])
      sizeDigest(ctx)
    else:
      0'u
  elif ctx.bits == 512 and ctx.bsize == 128:
    if len(data) >= 64:
      finalize512(ctx)
      beStore64(data, 0, ctx.state[0])
      beStore64(data, 8, ctx.state[1])
      beStore64(data, 16, ctx.state[2])
      beStore64(data, 24, ctx.state[3])
      beStore64(data, 32, ctx.state[4])
      beStore64(data, 40, ctx.state[5])
      beStore64(data, 48, ctx.state[6])
      beStore64(data, 56, ctx.state[7])
      sizeDigest(ctx)
    else:
      0'u
  elif ctx.bits == 256 and ctx.bsize == 128:
    if len(data) >= 32:
      finalize512(ctx)
      beStore64(data, 0, ctx.state[0])
      beStore64(data, 8, ctx.state[1])
      beStore64(data, 16, ctx.state[2])
      beStore64(data, 24, ctx.state[3])
      sizeDigest(ctx)
    else:
      0'u
  elif ctx.bits == 224 and ctx.bsize == 128:
    if len(data) >= 28:
      finalize512(ctx)
      beStore64(data, 0, ctx.state[0])
      beStore64(data, 8, ctx.state[1])
      beStore64(data, 16, ctx.state[2])
      beStore32(data, 24, uint32(ctx.state[3] shr 32))
      sizeDigest(ctx)
    else:
      0'u

proc finish*(ctx: var Sha2Context, pbytes: ptr byte,
             nbytes: uint): uint {.noinit.} =
  let ptrarr = cast[ptr UncheckedArray[byte]](pbytes)
  ctx.finish(ptrarr.toOpenArray(0, int(nbytes) - 1))

proc finish*(ctx: var Sha2Context): MDigest[ctx.bits] {.noinit.} =
  discard finish(ctx, result.data)

template declareDigest(DigestType: untyped) =
  proc digest*[B: bchar](HashType: typedesc[DigestType], data: openArray[B],
                         implementation: Sha2Implementation,
                         cpufeatures: set[CpuFeature] = {}
                        ): MDigest[HashType.bits] =
    var ctx: HashType
    ctx.init(implementation, cpufeatures)
    ctx.update(data)
    let res = ctx.finish()
    ctx.clear()
    res

  proc digest*[B: bchar](HashType: typedesc[DigestType], data: openArray[B],
                         cpufeatures: set[CpuFeature]): MDigest[HashType.bits] =
    digest(HashType, data, Sha2Implementation.Auto, cpufeatures)

  proc digest*(HashType: typedesc[DigestType], data: ptr byte, ulen: uint,
               implementation: Sha2Implementation,
               cpufeatures: set[CpuFeature] = {}): MDigest[HashType.bits] =
    var ctx: HashType
    ctx.init(implementation, cpufeatures)
    ctx.update(data, ulen)
    let res = ctx.finish()
    ctx.clear()
    res

  proc digest*(HashType: typedesc[DigestType], data: ptr byte, ulen: uint,
               cpufeatures: set[CpuFeature]): MDigest[HashType.bits] =
    digest(HashType, data, ulen, Sha2Implementation.Auto, cpufeatures)

declareDigest(sha224)
declareDigest(sha256)
declareDigest(sha384)
declareDigest(sha512)
declareDigest(sha512224)
declareDigest(sha512256)
