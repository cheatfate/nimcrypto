#
#
#                    NimCrypto
#        (c) Copyright 2023 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements ARGON2 Memory-Hard Function for Password Hashing
## and Proof-of-Work Applications designed by  Alex Biryukov, Daniel Dinu and
## Dmitry Khovratovich.
##
## This module implementation is made according to RFC9106
## https://www.rfc-editor.org/rfc/rfc9106.txt
##
## It supports both version 16 and 19 and all the variants Argon2d, Argon2i and
## Argon2id. It also could work in single-threaded and multi-threaded mode.

{.push raises: [].}

import utils, blake2

const
  ARGON2_BLOCK_SIZE = 1024
  ARGON2_QWORDS_IN_BLOCK = ((ARGON2_BLOCK_SIZE) div 8)
  ARGON2_PREHASH_DIGEST_LENGTH = 64
  ARGON2_PREHASH_SEED_LENGTH =
    ARGON2_PREHASH_DIGEST_LENGTH + (2 * sizeof(uint32))
  ARGON2_SYNC_POINTS = 4'u8
  ARGON2_ADDRESSES_IN_BLOCK = 128'u32
  ARGON2_MIN_MEMORY = (2 * ARGON2_SYNC_POINTS)
  ARGON2_DEFAULT_T_COST = 3'u32
  ARGON2_DEFAULT_M_COST = ARGON2_MIN_MEMORY
  ARGON2_DEFAULT_LANES = 1'u32
  ARGON2_DEFAULT_THREADS = 1'u32

  BlockSize = int(Blake2bContext[512].sizeDigest())

type
  Argon2Block = object
    value: array[ARGON2_QWORDS_IN_BLOCK, uint64]

  Argon2BlocksMap = ptr UncheckedArray[Argon2Block]

  Argon2BytesArray = object
    size: uint32
    data: UncheckedArray[byte]

  Argon2BytesArrayPtr = ptr Argon2BytesArray

  Argon2Version* {.pure.} = enum
    V10 = 0x10,
    V13 = 0x13

  Argon2Type* {.pure.} = enum
    TypeD = 0, TypeI = 1, TypeID = 2

  Argon2Pos = object of RootObj
    pass: uint32
    lane: uint32
    slice: uint8

  Argon2KdfSHM = object of RootObj
    kind: Argon2Type
    version: Argon2Version
    outLength: uint32
    lanes: uint32
    segmentLength: uint32
    memoryBlocks: uint32
    laneLength: uint32
    passes: uint32
    threads: uint32
    mCost: uint32
    tCost: uint32
    passwordPtr: Argon2BytesArrayPtr
    saltPtr: Argon2BytesArrayPtr
    secretPtr: Argon2BytesArrayPtr
    adPtr: Argon2BytesArrayPtr
    memoryPtr: Argon2BlocksMap

  Argon2KdfGCM = object of RootObj
    kind: Argon2Type
    version: Argon2Version
    outLength: uint32
    lanes: uint32
    segmentLength: uint32
    memoryBlocks: uint32
    laneLength: uint32
    passes: uint32
    threads: uint32
    mCost: uint32
    tCost: uint32
    passwordSeq: seq[byte]
    saltSeq: seq[byte]
    secretSeq: seq[byte]
    adSeq: seq[byte]
    memorySeq: seq[Argon2Block]

  Argon2Kdf = Argon2KdfSHM | Argon2KdfGCM

  Argon2ThreadData = object
    context: Argon2KdfSHM
    position: Argon2Pos

  Argon2ThreadDataPtr = ptr Argon2ThreadData

proc allocMem(size: Natural): pointer =
  allocShared0(size)

proc freeMem(data: pointer) =
  freeShared(cast[ptr byte](data))

proc transformG(a, b, c, d: var uint64) =
  a = a + b + 2 * (a and 0xFFFF_FFFF'u64) * (b and 0xFFFF_FFFF'u64)
  let da1 = d xor a
  d = ROR(da1, 32)
  c = c + d + 2 * (c and 0xFFFF_FFFF'u64) * (d and 0xFFFF_FFFF'u64)
  let bc1 = b xor c
  b = ROR(bc1, 24)
  a = a + b + 2 * (a and 0xFFFF_FFFF'u64) * (b and 0xFFFF_FFFF'u64)
  let da2 = d xor a
  d = ROR(da2, 16)
  c = c + d + 2 * (c and 0xFFFF_FFFF'u64) * (d and 0xFFFF_FFFF'u64)
  let bc2 = b xor c
  b = ROR(bc2, 63)

proc permutationP(v0, v1, v2, v3, v4, v5, v6, v7, v8,
                  v9, v10, v11, v12, v13, v14, v15: var uint64) =
  transformG(v0, v4, v8, v12)
  transformG(v1, v5, v9, v13)
  transformG(v2, v6, v10, v14)
  transformG(v3, v7, v11, v15)
  transformG(v0, v5, v10, v15)
  transformG(v1, v6, v11, v12)
  transformG(v2, v7, v8, v13)
  transformG(v3, v4, v9, v14)

proc permutationPcol(x: var array[ARGON2_QWORDS_IN_BLOCK, uint64], i: int) =
  let base = 16 * i
  permutationP(x[base + 0], x[base + 1], x[base + 2], x[base + 3],
               x[base + 4], x[base + 5], x[base + 6], x[base + 7],
               x[base + 8], x[base + 9], x[base + 10], x[base + 11],
               x[base + 12], x[base + 13], x[base + 14], x[base + 15])

proc permutationProw(x: var array[ARGON2_QWORDS_IN_BLOCK, uint64], i: int) =
  let base = 2 * i
  permutationP(x[base + 0], x[base + 1], x[base + 16], x[base + 17],
               x[base + 32], x[base + 33], x[base + 48], x[base + 49],
               x[base + 64], x[base + 65], x[base + 80], x[base + 81],
               x[base + 96], x[base + 97], x[base + 112], x[base + 113])

# else:
#   template transformG(a, b, c, d: untyped) =
#     a = a + b + 2 * (a and 0xFFFF_FFFF'u64) * (b and 0xFFFF_FFFF'u64)
#     let da1 = d xor a
#     d = ROR(da1, 32)
#     c = c + d + 2 * (c and 0xFFFF_FFFF'u64) * (d and 0xFFFF_FFFF'u64)
#     let bc1 = b xor c
#     b = ROR(bc1, 24)
#     a = a + b + 2 * (a and 0xFFFF_FFFF'u64) * (b and 0xFFFF_FFFF'u64)
#     let da2 = d xor a
#     d = ROR(da2, 16)
#     c = c + d + 2 * (c and 0xFFFF_FFFF'u64) * (d and 0xFFFF_FFFF'u64)
#     let bc2 = b xor c
#     b = ROR(bc2, 63)

#   template permutationP(v0, v1, v2, v3, v4, v5, v6, v7, v8,
#                         v9, v10, v11, v12, v13, v14, v15: untyped) =
#     transformG(v0, v4, v8, v12)
#     transformG(v1, v5, v9, v13)
#     transformG(v2, v6, v10, v14)
#     transformG(v3, v7, v11, v15)
#     transformG(v0, v5, v10, v15)
#     transformG(v1, v6, v11, v12)
#     transformG(v2, v7, v8, v13)
#     transformG(v3, v4, v9, v14)

#   template permutationPcol(x, i: untyped) =
#     let base = 16 * i
#     permutationP(x[base + 0], x[base + 1], x[base + 2], x[base + 3],
#                  x[base + 4], x[base + 5], x[base + 6], x[base + 7],
#                  x[base + 8], x[base + 9], x[base + 10], x[base + 11],
#                  x[base + 12], x[base + 13], x[base + 14], x[base + 15])

#   template permutationProw(x, i: untyped) =
#     let base = 2 * i
#     permutationP(x[base + 0], x[base + 1], x[base + 16], x[base + 17],
#                  x[base + 32], x[base + 33], x[base + 48], x[base + 49],
#                  x[base + 64], x[base + 65], x[base + 80], x[base + 81],
#                  x[base + 96], x[base + 97], x[base + 112], x[base + 113])

func init(t: typedesc[Argon2Block]): Argon2Block {.noinit.} =
  Argon2Block()

func init(blck: var Argon2Block) {.noinit.} =
  for i in 0 ..< len(blck.value):
    blck.value[i] = 0'u64

proc copyBlock(dst: var Argon2Block, src: Argon2Block) =
  copyMem(dst.value, 0, src.value, 0, ARGON2_QWORDS_IN_BLOCK)

proc xorBlock(dst: var Argon2Block, src: Argon2Block) =
  for i in 0 ..< ARGON2_QWORDS_IN_BLOCK:
    dst.value[i] = dst.value[i] xor src.value[i]

proc loadBlock(dst: var Argon2Block, data: openArray[byte]) =
  for i in 0 ..< ARGON2_QWORDS_IN_BLOCK:
    dst.value[i] = leLoad64(data, i * sizeof(uint64))

proc storeBlock(dst: var openArray[byte], src: Argon2Block) =
  for i in 0 ..< ARGON2_QWORDS_IN_BLOCK:
    leStore64(dst, i * sizeof(uint64), src.value[i])

proc blake2bLong(dst: var openArray[byte], src: openArray[byte]) =
  var
    ctx: Blake2bContext[512]
    outBytes: array[BlockSize, byte]
    inpBytes: array[BlockSize, byte]
    outlenBytes: array[sizeof(uint32), byte]

  leStore32(outlenBytes, 0, uint32(len(dst)))

  if len(dst) > BlockSize:
    ctx.init(BlockSize)
    ctx.update(outlenBytes)
    ctx.update(src)
    discard ctx.finish(outBytes)
    copyMem(dst, 0, outBytes, 0, BlockSize div 2)
    var
      offset = BlockSize div 2
      bytesLeft = len(dst) - (BlockSize div 2)

    while bytesLeft > BlockSize:
      copyMem(inpBytes, 0, outBytes, 0, BlockSize)
      ctx.init()
      ctx.update(inpBytes)
      discard ctx.finish(outBytes)
      copyMem(dst, offset, outBytes, 0, BlockSize div 2)
      offset += (BlockSize div 2)
      bytesLeft -= (BlockSize div 2)

    copyMem(inpBytes, 0, outBytes, 0, BlockSize)
    ctx.init()
    ctx.update(inpBytes)
    discard ctx.finish(outBytes.toOpenArray(0, bytesLeft - 1))
    copyMem(dst, offset, outBytes, 0, bytesLeft)
  else:
    ctx.init(len(dst))
    ctx.update(outlenBytes)
    ctx.update(src)
    discard ctx.finish(dst)

  ctx.clear()

proc fillFirstBlocks(ctx: var Argon2Kdf, blockhash: var openArray[byte]) =
  var blockhashBytes: array[ARGON2_BLOCK_SIZE, byte]

  for i in 0'u32 ..< ctx.lanes:
    leStore32(blockhash, ARGON2_PREHASH_DIGEST_LENGTH, 0'u32)
    leStore32(blockhash, ARGON2_PREHASH_DIGEST_LENGTH + 4, uint32(i))
    blake2bLong(blockhashBytes,
                blockhash.toOpenArray(0, ARGON2_PREHASH_SEED_LENGTH - 1))
    when ctx is Argon2KdfGCM:
      loadBlock(ctx.memorySeq[i * ctx.laneLength + 0], blockhashBytes)
      leStore32(blockhash, ARGON2_PREHASH_DIGEST_LENGTH, 1'u32)
      blake2bLong(blockhashBytes,
                  blockhash.toOpenArray(0, ARGON2_PREHASH_SEED_LENGTH - 1))
      loadBlock(ctx.memorySeq[i * ctx.laneLength + 1], blockhashBytes)
    else:
      loadBlock(ctx.memoryPtr[i * ctx.laneLength + 0], blockhashBytes)
      leStore32(blockhash, ARGON2_PREHASH_DIGEST_LENGTH, 1'u32)
      blake2bLong(blockhashBytes,
                  blockhash.toOpenArray(0, ARGON2_PREHASH_SEED_LENGTH - 1))
      loadBlock(ctx.memoryPtr[i * ctx.laneLength + 1], blockhashBytes)

proc fillBlock(prevBlock, refBlock: Argon2Block, nextBlock: var Argon2Block,
               withXor: bool) {.noinit.} =
  var
    blockR = Argon2Block.init()
    tmp = Argon2Block.init()

  copyBlock(blockR, refBlock)
  xorBlock(blockR, prevBlock)
  copyBlock(tmp, blockR)
  if withXor: xorBlock(tmp, nextBlock)
  for i in 0 ..< 8:
    permutationPcol(blockR.value, i)
  for i in 0 ..< 8:
    permutationProw(blockR.value, i)
  copyBlock(nextBlock, tmp)
  xorBlock(nextBlock, blockR)

proc nextAddresses(addressBlock: var Argon2Block, inputBlock: var Argon2Block,
                   zeroBlock: Argon2Block) =
  inc(inputBlock.value[6])
  fillBlock(zeroBlock, inputBlock, addressBlock, false)
  fillBlock(zeroBlock, addressBlock, addressBlock, false)

proc dataIndepAddressing(ctx: Argon2Kdf, pass: uint32, slice: uint8): bool =
  case ctx.kind
  of Argon2Type.TypeI:
    true
  of Argon2Type.TypeID:
    (pass == 0'u32) and (slice < (ARGON2_SYNC_POINTS div 2))
  of Argon2Type.TypeD:
    false

proc indexAlpha(ctx: Argon2Kdf, pass: uint32, slice: uint8, index: uint32,
                prand: uint32, sameLine: bool): uint32 =
  let (startPos, refAreaSz) =
    if pass == 0'u32:
      if slice == 0'u8:
        (0'u32, index - 1'u32)
      elif sameLine:
        (0'u32, slice * ctx.segmentLength + index - 1'u32)
      else:
        if index == 0:
          (0'u32, slice * ctx.segmentLength - 1'u32)
        else:
          (0'u32, slice * ctx.segmentLength)
    else:
      let
        areaSz =
          if sameLine:
            ctx.laneLength - ctx.segmentLength + index - 1'u32
          else:
            if index == 0'u32:
              ctx.laneLength - ctx.segmentLength - 1'u32
            else:
              ctx.laneLength - ctx.segmentLength
        startPos =
          if slice != ARGON2_SYNC_POINTS - 1'u32:
            (slice + 1) * ctx.segmentLength
          else:
            0'u32
      (startPos, areaSz)
  var relPos = prand
  relPos = uint32((uint64(relPos) * uint64(relPos)) shr 32)
  relPos = ref_area_sz - 1'u32 - uint32((uint64(ref_area_sz) * uint64(relPos)) shr 32)
  let res = (startPos + relPos) mod ctx.laneLength
  res

proc fillSegment(ctx: var Argon2Kdf, pass: uint32, lane: uint32,
                 slice: uint8) {.noinit.} =
  var
    addressBlock: Argon2Block
    zeroBlock: Argon2Block
    inputBlock: Argon2Block

  if dataIndepAddressing(ctx, pass, slice):
    init(zeroBlock)
    init(inputBlock)

    inputBlock.value[0] = pass;
    inputBlock.value[1] = lane;
    inputBlock.value[2] = slice;
    inputBlock.value[3] = ctx.memoryBlocks
    inputBlock.value[4] = ctx.passes
    inputBlock.value[5] = uint32(ctx.kind)
  else:
    init(inputBlock)

  let
    startIndex =
      if (pass == 0'u32) and (slice == 0'u8):
        if dataIndepAddressing(ctx, pass, slice):
          nextAddresses(addressBlock, inputBlock, zeroBlock)
        2'u32
      else:
        0'u32
  var
    currentOffset = lane * ctx.laneLength + slice * ctx.segmentLength +
                    startIndex
    prevOffset =
      if currentOffset mod ctx.laneLength == 0:
        currentOffset + ctx.laneLength - 1'u32
      else:
        currentOffset - 1'u32

  for j in startIndex ..< ctx.segmentLength:
    if currentOffset mod ctx.laneLength == 1'u32:
      prevOffset = currentOffset - 1

    let
      randomNumber =
        if dataIndepAddressing(ctx, pass, slice):
          if (j mod ARGON2_ADDRESSES_IN_BLOCK) == 0'u32:
            nextAddresses(addressBlock, inputBlock, zeroBlock)
          addressBlock.value[int(j mod ARGON2_ADDRESSES_IN_BLOCK)]
        else:
          when ctx is Argon2KdfGCM:
            ctx.memorySeq[prevOffset].value[0]
          else:
            ctx.memoryPtr[prevOffset].value[0]
      refLane =
        if (pass == 0'u32) and (slice == 0'u32):
          lane
        else:
          uint32(randomNumber shr 32) mod uint32(ctx.lanes)
      refIndex = indexAlpha(ctx, pass, slice, j,
                            uint32(randomNumber and 0xFFFF_FFFF'u64),
                            refLane == lane)
    let
      rindex = ctx.laneLength * refLane + refIndex
      cindex = currentOffset

    if ctx.version == Argon2Version.V10:
      when ctx is Argon2KdfGCM:
        fillBlock(ctx.memorySeq[prevOffset], ctx.memorySeq[rindex],
                  ctx.memorySeq[cindex], false)
      else:
        fillBlock(ctx.memoryPtr[prevOffset], ctx.memoryPtr[rindex],
                  ctx.memoryPtr[cindex], false)
      continue

    if pass == 0:
      when ctx is Argon2KdfGCM:
        fillBlock(ctx.memorySeq[prevOffset], ctx.memorySeq[rindex],
                  ctx.memorySeq[cindex], false)
      else:
        fillBlock(ctx.memoryPtr[prevOffset], ctx.memoryPtr[rindex],
                  ctx.memoryPtr[cindex], false)

    else:
      when ctx is Argon2KdfGCM:
        fillBlock(ctx.memorySeq[prevOffset], ctx.memorySeq[rindex],
                  ctx.memorySeq[cindex], true)
      else:
        fillBlock(ctx.memoryPtr[prevOffset], ctx.memoryPtr[rindex],
                  ctx.memoryPtr[cindex], true)
    inc(currentOffset)
    inc(prevOffset)

proc fillSegmentThr(arg: Argon2ThreadDataPtr) {.thread, nimcall.} =
  var ctx = arg[].context
  let position = arg[].position
  ctx.fillSegment(position.pass, position.lane, position.slice)

proc fillMemoryBlocksMT(ctx: var Argon2KdfSHM) =
  when compileOption("threads"):
    let
      lanes = int(ctx.lanes)
      contexts = cast[ptr UncheckedArray[Argon2ThreadData]](
                     allocMem(sizeof(Argon2ThreadData) * lanes))
    if isNil(contexts):
      return
    defer:
      freeMem(cast[pointer](contexts))
    let threads = cast[ptr UncheckedArray[Thread[Argon2ThreadDataPtr]]](
                    allocMem(sizeof(Thread[Argon2ThreadDataPtr]) * lanes))

    if isNil(threads):
      return
    defer:
      freeMem(cast[pointer](threads))

    for r in 0 ..< ctx.passes:
      for s in 0'u8 ..< ARGON2_SYNC_POINTS:
        for j in 0'u32 ..< ctx.lanes:
          if j >= ctx.threads:
            joinThread(threads[j - ctx.threads])

          contexts[j].context = ctx
          contexts[j].position = Argon2Pos(pass: r, lane: j, slice: s)

          try:
            createThread(threads[j], fillSegmentThr, addr contexts[j])
          except ResourceExhaustedError:
            for k in 0 ..< j:
              joinThread(threads[k])
            return

        for j in (ctx.lanes - ctx.threads) ..< ctx.lanes:
          joinThread(threads[j])

proc fillMemoryBlocksST(ctx: var Argon2Kdf) =
  for r in 0 ..< ctx.passes:
    for s in 0'u8 ..< ARGON2_SYNC_POINTS:
      for j in 0'u32 ..< ctx.lanes:
        fillSegment(ctx, r, j, s)

proc fillMemoryBlocks(ctx: var Argon2KdfGCM) =
  doAssert(ctx.threads == 1'u32)
  ctx.fillMemoryBlocksST()

proc fillMemoryBlocks(ctx: var Argon2KdfSHM) =
  if ctx.threads > 1'u32:
    ctx.fillMemoryBlocksMT()
  else:
    ctx.fillMemoryBlocksST()

proc initialHash(actx: var Argon2Kdf, blockhash: var openArray[byte]) =
  var
    value: array[sizeof(uint32), byte]
    args: array[6, uint32]
    bctx: Blake2bContext[512]

  args[0] = actx.lanes
  args[1] = actx.outLength
  args[2] = actx.mCost
  args[3] = actx.tCost
  args[4] = uint32(actx.version)
  args[5] = uint32(actx.kind)

  bctx.init()

  for i in 0 ..< len(args):
    leStore32(value, 0, args[i])
    bctx.update(value)

  when actx is Argon2KdfGCM:
    template hashBytesField(argname: untyped) =
      leStore32(value, 0, uint32(len(argname)))
      bctx.update(value)
      if len(argname) > 0:
        bctx.update(argname)
    hashBytesField(actx.passwordSeq)
    hashBytesField(actx.saltSeq)
    hashBytesField(actx.secretSeq)
    hashBytesField(actx.adSeq)
  else:
    template hashBytesField(argname: untyped) =
      leStore32(value, 0, (argname)[].size)
      bctx.update(value)
      if not(isNil(argname)):
        bctx.update(cast[ptr byte](addr argname[].data[0]), (argname)[].size)
        freeMem(cast[pointer](argname))
        argname = nil
    hashBytesField(actx.passwordPtr)
    hashBytesField(actx.saltPtr)
    hashBytesField(actx.secretPtr)
    hashBytesField(actx.adPtr)

  discard bctx.finish(
    blockhash.toOpenArray(0, ARGON2_PREHASH_DIGEST_LENGTH - 1))

  # bctx.clear()

proc toSeqByte[T](data: openArray[T]): seq[byte] =
  when T is char:
    @data.toOpenArrayByte(0, len(data) - 1)
  else:
    @data

proc toBytesArrayPtr[T](data: openArray[T]): Argon2BytesArrayPtr =
  if len(data) > 0:
    let
      length = (((len(data) + sizeof(uint32) + 7) div 8) + 1) * 8
      res = cast[Argon2BytesArrayPtr](allocMem(length))
    res[].size = uint32(len(data))
    copyMem(cast[pointer](addr res.data), unsafeAddr data[0], len(data))
    res
  else:
    nil

proc init[K, L, M, N](
       t: typedesc[Argon2KdfGCM],
       kind: Argon2Type,
       password: openArray[K],
       salt: openArray[L],
       ad: openArray[M],
       secret: openArray[N],
       version: Argon2Version,
       tCost: uint32,
       mCost: uint32,
       lanes: uint32,
       threads: uint32,
       outputLength: uint32,
     ): Argon2KdfGCM =
  Argon2KdfGCM(
    passwordSeq: password.toSeqByte(),
    saltSeq: salt.toSeqByte(),
    adSeq: ad.toSeqByte(),
    secretSeq: secret.toSeqByte(),
    outLength: outputLength,
    tCost: tCost,
    mCost: mCost,
    lanes: lanes,
    threads: threads,
    version: version,
    kind: kind
  )

proc init[K, L, M, N](
       t: typedesc[Argon2KdfSHM],
       kind: Argon2Type,
       password: openArray[K],
       salt: openArray[L],
       ad: openArray[M],
       secret: openArray[N],
       version: Argon2Version,
       tCost: uint32,
       mCost: uint32,
       lanes: uint32,
       threads: uint32,
       outputLength: uint32,
     ): Argon2KdfSHM =
  Argon2KdfSHM(
    passwordPtr: password.toBytesArrayPtr(),
    saltPtr: salt.toBytesArrayPtr(),
    adPtr: ad.toBytesArrayPtr(),
    secretPtr: secret.toBytesArrayPtr(),
    outLength: outputLength,
    tCost: tCost,
    mCost: mCost,
    lanes: lanes,
    threads: threads,
    version: version,
    kind: kind
  )

proc free(ctx: var Argon2Kdf) =
  when ctx is Argon2KdfGCM:
    template freeSecret(argname: untyped) =
      if len(argname) > 0:
        argname.reset()
    freeSecret(ctx.passwordSeq)
    ctx.saltSeq.freeSecret()
    ctx.secretSeq.freeSecret()
    ctx.adSeq.freeSecret()
    ctx.memorySeq.reset()
  else:
    template freeSecret(argname: untyped) =
      if not(isNil(argname)):
        freeMem(cast[pointer](argname))
        argname = nil
    ctx.passwordPtr.freeSecret()
    ctx.saltPtr.freeSecret()
    ctx.secretPtr.freeSecret()
    ctx.adPtr.freeSecret()
    freeMem(cast[pointer](ctx.memoryPtr))
    ctx.memoryPtr = nil

proc allocate(ctx: var Argon2Kdf) =
  var blockhash: array[ARGON2_PREHASH_SEED_LENGTH, byte]
  when ctx is Argon2KdfGCM:
    ctx.memorySeq = newSeq[Argon2Block](ctx.memoryBlocks)
  else:
    let size = Natural(ctx.memoryBlocks) * sizeof(Argon2Block)
    ctx.memoryPtr =
      cast[Argon2BlocksMap](allocMem(size))
  initialHash(ctx, blockhash)
  fillFirstBlocks(ctx, blockhash)

proc finalize(ctx: var Argon2Kdf, outBytes: var openArray[byte]) =
  var
    blockhash: Argon2Block
    blockhashBytes: array[ARGON2_BLOCK_SIZE, byte]

  when ctx is Argon2KdfGCM:
    copyBlock(blockhash, ctx.memorySeq[ctx.laneLength - 1])
    for j in 1 ..< ctx.lanes:
      let lastBlockInLane = j * ctx.laneLength + (ctx.laneLength - 1)
      xorBlock(blockhash, ctx.memorySeq[lastBlockInLane])
  else:
    copyBlock(blockhash, ctx.memoryPtr[ctx.laneLength - 1])
    for j in 1 ..< ctx.lanes:
      let lastBlockInLane = j * ctx.laneLength + (ctx.laneLength - 1)
      xorBlock(blockhash, ctx.memoryPtr[lastBlockInLane])

  storeBlock(blockhashBytes, blockhash)
  blake2bLong(outBytes, blockhashBytes)

proc derive(ctx: var Argon2Kdf, outBytes: var openArray[byte]) =
  let
    mBlocks =
      if (ctx.mCost < 2 * ARGON2_SYNC_POINTS * ctx.lanes):
        2 * ARGON2_SYNC_POINTS * ctx.lanes
      else:
        ctx.mCost

  ctx.segmentLength = mBlocks div (ctx.lanes * ARGON2_SYNC_POINTS)
  ctx.memoryBlocks = ctx.segmentLength * (ctx.lanes * ARGON2_SYNC_POINTS)
  ctx.passes = ctx.tCost
  ctx.laneLength = ctx.segmentLength * ARGON2_SYNC_POINTS

  ctx.allocate()
  ctx.fillMemoryBlocks()
  ctx.finalize(outbytes)

proc argon2*[K, L, M, N](
       kind: Argon2Type,
       password: openArray[K],
       salt: openArray[L],
       ad: openArray[M],
       secret: openArray[N],
       output: var openarray[byte],
       passes: uint32 = ARGON2_DEFAULT_T_COST,
       parallelism: uint32 = ARGON2_DEFAULT_LANES,
       memoryCost: uint32 = ARGON2_DEFAULT_M_COST,
       threads: uint32 = ARGON2_DEFAULT_THREADS,
       version = Argon2Version.V13
     ): int =

  when not((K is byte) or (K is char)):
    {.fatal: "Choosen password type is not supported!".}

  when not((L is byte) or (L is char)):
    {.fatal: "Choosen salt type is not supported!".}

  when not((M is byte) or (M is char)):
    {.fatal: "Choosen authentication data type is not supported!".}

  when not((N is byte) or (N is char)):
    {.fatal: "Choosen secret data type is not supported!".}

  when nimvm:
    doAssert(threads == 1'u32,
             "Nim VM do not support multithreading environment, " &
             "`threads` should be 1")
  when not(compileOption("threads")):
    doAssert(threads == 1'u32,
             "Project should be compiled with --threads:on option to enable " &
             "multithreading support")
  doAssert(len(salt) > 0, "Missing `salt` value")
  doAssert(threads <= parallelism,
           "Number of threads should be less or equal to number of lanes")
  doAssert(memoryCost >= 8 * parallelism,
           "Memory cost should greater or equal than 8 times the number " &
           "of lanes")

  when nimvm:
    var ctx1 = Argon2KdfGCM.init(kind, password, salt, ad, secret, version,
                                passes, memoryCost, parallelism, threads,
                                uint32(len(output)))
    ctx1.derive(output)
    ctx1.free()
    len(output)
  else:
    var ctx2 = Argon2KdfSHM.init(kind, password, salt, ad, secret, version,
                                passes, memoryCost, parallelism, threads,
                                uint32(len(output)))
    ctx2.derive(output)
    ctx2.free()
    len(output)

proc argon2*[K, L, M, N](
       kind: Argon2Type,
       password: openArray[K],
       salt: openArray[L],
       ad: openArray[M],
       secret: openArray[N],
       outlen: static[Natural],
       passes: uint32 = ARGON2_DEFAULT_T_COST,
       parallelism: uint32 = ARGON2_DEFAULT_LANES,
       memoryCost: uint32 = ARGON2_DEFAULT_M_COST,
       threads: uint32 = ARGON2_DEFAULT_THREADS,
       version = Argon2Version.V13
     ): array[outlen, byte] =
  discard argon2(kind, password, salt, ad, secret, result, passes, parallelism,
                 memoryCost, threads, version)
