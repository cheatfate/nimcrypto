#
#
#                    NimCrypto
#        (c) Copyright 2016 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements various Block Cipher Modes.
##
## The five modes currently supported:
## * ECB (Electronic Code Book)
## * CBC (Cipher Block Chaining)
## * CFB (Cipher FeedBack)
## * OFB (Output FeedBack)
## * CTR (Counter)
##
## Tests made according to official test vectors (Appendix F)
## http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

import cipher, utils

const
  MaxBlockSize = 256
  MaxBlockBytesSize = MaxBlockSize shr 3

type
  BlockCipherContext = ref object of RootRef
    sizeBlock: int
    sizeKey: int

  ECB*[T] = ref object of BlockCipherContext
    cipher: T
    tmp: array[MaxBlockBytesSize, uint8]

  CBC*[T] = ref object of BlockCipherContext
    cipher: T
    iv: array[MaxBlockBytesSize, uint8]
    tmp: array[MaxBlockBytesSize, uint8]

  OFB*[T] = ref object of BlockCipherContext
    cipher: T
    iv: array[MaxBlockBytesSize, uint8]

  CFB*[T] = ref object of BlockCipherContext
    cipher: T
    iv: array[MaxBlockBytesSize, uint8]

  CTR*[T] = ref object of BlockCipherContext
    cipher: T
    iv: array[MaxBlockBytesSize, uint8]
    ecount: array[MaxBlockBytesSize, uint8]
    num: uint

## ECB (Electronic Code Book) Mode

proc init*[T](ctx: ECB[T], keyBytes: ptr uint8) =
  mixin init
  assert(not isNil(ctx) and not isNil(keyBytes))
  ctx.cipher = T()
  init(ctx.cipher, keyBytes)
  ctx.sizeBlock = ctx.cipher.sizeBlock
  ctx.sizeKey = ctx.cipher.sizeKey
  doAssert(ctx.sizeBlock <= MaxBlockSize)

proc encrypt*[T](ctx: ECB[T], inp: ptr uint8, oup: ptr uint8,
                 length: uint): uint {.discardable.} =
  mixin encrypt
  assert(not isNil(ctx) and not isNil(inp) and not isNil(oup))
  assert(length != 0)

  var blen = uint(ctx.sizeBlock shr 3)
  var ip = cast[ptr UncheckedArray[uint8]](inp)
  var op = cast[ptr UncheckedArray[uint8]](oup)
  var tp = cast[ptr UncheckedArray[uint8]](addr ctx.tmp[0])

  var i = length
  while i != 0:
    if i < blen:
      copyMem(tp, ip, i)
      ctx.cipher.encrypt(cast[ptr uint8](tp), cast[ptr uint8](op))
      break
    ctx.cipher.encrypt(cast[ptr uint8](ip), cast[ptr uint8](op))
    i = i - blen
    ip = cast[ptr UncheckedArray[uint8]](cast[uint](ip) + blen)
    op = cast[ptr UncheckedArray[uint8]](cast[uint](op) + blen)

proc decrypt*[T](ctx: ECB[T], inp: ptr uint8, oup: ptr uint8,
                 length: uint): uint {.discardable.} =
  mixin decrypt
  assert(not isNil(ctx) and not isNil(inp) and not isNil(oup))
  assert(length != 0)
  assert(length mod uint(ctx.sizeBlock shr 3) == 0)

  var blen = uint(ctx.sizeBlock shr 3)
  var ip = cast[ptr UncheckedArray[uint8]](inp)
  var op = cast[ptr UncheckedArray[uint8]](oup)
  var i = length
  while i != 0:
    ctx.cipher.decrypt(cast[ptr uint8](ip), cast[ptr uint8](op))
    i = i - blen
    ip = cast[ptr UncheckedArray[uint8]](cast[uint](ip) + blen)
    op = cast[ptr UncheckedArray[uint8]](cast[uint](op) + blen)

## CBC (Cipher Block Chaining) Mode

proc init*[T](ctx: CBC[T], keyBytes: ptr uint8, iv: ptr uint8) =
  mixin init
  assert(not isNil(ctx) and not isNil(keyBytes) and not isNil(iv))
  ctx.cipher = T()
  init(ctx.cipher, keyBytes)
  ctx.sizeBlock = ctx.cipher.sizeBlock
  ctx.sizeKey = ctx.cipher.sizeKey
  doAssert(ctx.sizeBlock <= MaxBlockSize)
  copyMem(addr ctx.iv[0], iv, ctx.sizeBlock shr 3)

proc encrypt*[T](ctx: CBC[T], inp: ptr uint8, oup: ptr uint8,
                 length: uint): uint {.discardable.} =
  mixin encrypt
  assert(not isNil(ctx) and not isNil(inp) and not isNil(oup))
  assert(length != 0)

  var blen = uint(ctx.sizeBlock shr 3)
  var ip = cast[ptr UncheckedArray[uint8]](inp)
  var op = cast[ptr UncheckedArray[uint8]](oup)
  var cp = cast[ptr UncheckedArray[uint8]](addr ctx.iv[0])

  var i = length
  while i != 0:
    var n = 0'u
    while (n < blen) and (n < length):
      op[n] = ip[n] xor cp[n]
      inc(n)
    while n < blen:
      op[n] = cp[n]
      inc(n)
    ctx.cipher.encrypt(cast[ptr uint8](op), cast[ptr uint8](op))
    cp = op
    if i < blen:
      break
    i = i - blen
    ip = cast[ptr UncheckedArray[uint8]](cast[uint](ip) + blen)
    op = cast[ptr UncheckedArray[uint8]](cast[uint](op) + blen)
  copyMem(addr ctx.iv[0], cp, blen)

proc decrypt*[T](ctx: CBC[T], inp: ptr uint8, oup: ptr uint8,
                 length: uint): uint {.discardable.} =
  mixin decrypt
  assert(not isNil(ctx) and not isNil(inp) and not isNil(oup))
  assert(length != 0)

  let blen = uint(ctx.sizeBlock shr 3)
  var ip = cast[ptr UncheckedArray[uint8]](inp)
  var op = cast[ptr UncheckedArray[uint8]](oup)
  var tp = cast[ptr UncheckedArray[uint8]](addr ctx.tmp[0])
  var cp = cast[ptr UncheckedArray[uint8]](addr ctx.iv[0])

  var i = length
  while i != 0:
    var n = 0'u
    ctx.cipher.decrypt(cast[ptr uint8](ip), cast[ptr uint8](tp))
    while (n < blen) and (n < length):
      var c = ip[n]
      op[n] = tp[n] xor cp[n]
      cp[n] = c
      inc(n)
    if i < blen:
      while n < blen:
        cp[n] = ip[n]
      break
    i = i - blen
    ip = cast[ptr UncheckedArray[uint8]](cast[uint](ip) + blen)
    op = cast[ptr UncheckedArray[uint8]](cast[uint](op) + blen)

## CTR (Counter) Mode

proc inc128(counter: ptr UncheckedArray[uint8]) =
  var n = 16'u32
  var c = 1'u32
  while true:
    dec(n)
    c = c + counter[n]
    counter[n] = cast[uint8](c)
    c = c shr 8
    if n == 0:
      break

proc inc256(counter: ptr UncheckedArray[uint8]) =
  var n = 32'u32
  var c = 1'u32
  while true:
    dec(n)
    c = c + counter[n]
    counter[n] = cast[uint8](c)
    c = c shr 8
    if n == 0:
      break

proc init*[T](ctx: CTR[T], keyBytes: ptr uint8, iv: ptr uint8) =
  mixin init
  assert(not isNil(ctx) and not isNil(keyBytes) and not isNil(iv))
  ctx.cipher = T()
  init(ctx.cipher, keyBytes)
  ctx.sizeBlock = ctx.cipher.sizeBlock
  ctx.sizeKey = ctx.cipher.sizeKey
  doAssert(ctx.sizeBlock <= MaxBlockSize)
  copyMem(addr ctx.iv[0], iv, ctx.sizeBlock shr 3)

proc encrypt*[T](ctx: CTR[T], inp: ptr uint8, oup: ptr uint8,
                 length: uint): uint {.discardable.} =
  mixin encrypt
  assert(not isNil(ctx) and not isNil(inp) and not isNil(oup))
  assert(length != 0)
  assert(ctx.sizeBlock == 128 or ctx.sizeBlock == 256)
  var n = ctx.num
  var i = 0'u
  var ip = cast[ptr UncheckedArray[uint8]](inp)
  var op = cast[ptr UncheckedArray[uint8]](oup)
  var cp = cast[ptr UncheckedArray[uint8]](addr ctx.iv[0])
  let mask = uint(ctx.sizeBlock shr 3)

  while i < length:
    if n == 0:
      ctx.cipher.encrypt(addr ctx.iv[0], addr ctx.ecount[0])
      if ctx.sizeBlock == 128:
        inc128(cp)
      elif ctx.sizeBlock == 256:
        inc256(cp)
    op[i] = cast[uint8](ip[i] xor ctx.ecount[n])
    inc(i)
    n = (n + 1) mod mask

  ctx.num = uint(n)
  result = ctx.num

proc decrypt*[T](ctx: CTR[T], inp: ptr uint8, oup: ptr uint8,
                 length: uint): uint {.discardable, inline.} =
  mixin encrypt
  result = encrypt(ctx, inp, oup, length)

## OFB (Output Feedback) Mode

proc init*[T](ctx: OFB[T], keyBytes: ptr uint8, iv: ptr uint8) =
  mixin init
  assert(not isNil(ctx) and not isNil(keyBytes) and not isNil(iv))
  ctx.cipher = T()
  init(ctx.cipher, keyBytes)
  ctx.sizeBlock = ctx.cipher.sizeBlock
  ctx.sizeKey = ctx.cipher.sizeKey
  doAssert(ctx.sizeBlock <= MaxBlockSize)
  copyMem(addr ctx.iv[0], iv, ctx.sizeBlock shr 3)

proc encrypt*[T](ctx: OFB[T], inp: ptr uint8, oup: ptr uint8,
                 length: uint): uint {.discardable.} =
  mixin encrypt
  assert(not isNil(ctx) and not isNil(inp) and not isNil(oup))
  assert(length != 0)
  assert(ctx.sizeBlock == 128 or ctx.sizeBlock == 256)
  var n = 0
  var i = 0'u
  var ip = cast[ptr UncheckedArray[uint8]](inp)
  var op = cast[ptr UncheckedArray[uint8]](oup)
  var cp = cast[ptr UncheckedArray[uint8]](addr ctx.iv[0])
  let mask = ctx.sizeBlock shr 3

  while i < length:
    if n == 0:
      ctx.cipher.encrypt(cast[ptr uint8](cp), cast[ptr uint8](cp))
    op[i] = ip[i] xor cp[n]
    inc(i)
    n = (n + 1) mod mask

proc decrypt*[T](ctx: OFB[T], inp: ptr uint8, oup: ptr uint8,
                 length: uint): uint {.discardable, inline.} =
  mixin encrypt
  result = encrypt(ctx, inp, oup, length)

## CFB (Cipher Feedback) Mode

proc init*[T](ctx: CFB[T], keyBytes: ptr uint8, iv: ptr uint8) =
  mixin init
  assert(not isNil(ctx) and not isNil(keyBytes) and not isNil(iv))
  ctx.cipher = T()
  init(ctx.cipher, keyBytes)
  ctx.sizeBlock = ctx.cipher.sizeBlock
  ctx.sizeKey = ctx.cipher.sizeKey
  doAssert(ctx.sizeBlock <= MaxBlockSize)
  copyMem(addr ctx.iv[0], iv, ctx.sizeBlock shr 3)

proc encrypt*[T](ctx: CFB[T], inp: ptr uint8, oup: ptr uint8,
                 length: uint): uint {.discardable.} =
  mixin encrypt
  assert(not isNil(ctx) and not isNil(inp) and not isNil(oup))
  assert(length != 0)
  var n = 0
  var i = 0'u
  var ip = cast[ptr UncheckedArray[uint8]](inp)
  var op = cast[ptr UncheckedArray[uint8]](oup)
  var cp = cast[ptr UncheckedArray[uint8]](addr ctx.iv[0])
  let mask = ctx.sizeBlock shr 3

  while i < length:
    if n == 0:
      ctx.cipher.encrypt(cast[ptr uint8](cp), cast[ptr uint8](cp))
    cp[n] = cp[n] xor ip[i]
    op[i] = cp[n]
    inc(i)
    n = (n + 1) mod mask
  result = (uint)n

proc decrypt*[T](ctx: CFB[T], inp: ptr uint8, oup: ptr uint8,
                 length: uint): uint {.discardable, inline.} =
  mixin encrypt
  assert(not isNil(ctx) and not isNil(inp) and not isNil(oup))
  assert(length != 0)
  var n = 0
  var i = 0'u
  var ip = cast[ptr UncheckedArray[uint8]](inp)
  var op = cast[ptr UncheckedArray[uint8]](oup)
  var cp = cast[ptr UncheckedArray[uint8]](addr ctx.iv[0])
  let mask = ctx.sizeBlock shr 3

  while i < length:
    if n == 0:
      ctx.cipher.encrypt(cast[ptr uint8](cp), cast[ptr uint8](cp))
    let c = ip[i]
    op[i] = cp[n] xor c
    cp[n] = c
    inc(i)
    n = (n + 1) mod mask
  result = (uint)n
