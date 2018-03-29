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

import utils

{.deadCodeElim:on.}

const
  MaxBlockSize = 256
  MaxBlockBytesSize = MaxBlockSize shr 3

type
  ECB*[T] = object
    cipher: T
    tmp: array[MaxBlockBytesSize, byte]

  CBC*[T] = object
    cipher: T
    iv: array[MaxBlockBytesSize, byte]
    tmp: array[MaxBlockBytesSize, byte]

  OFB*[T] = object
    cipher: T
    iv: array[MaxBlockBytesSize, byte]

  CFB*[T] = object
    cipher: T
    iv: array[MaxBlockBytesSize, byte]

  CTR*[T] = object
    cipher: T
    iv: array[MaxBlockBytesSize, byte]
    ecount: array[MaxBlockBytesSize, byte]
    num: uint

## ECB (Electronic Code Book) Mode

template sizeBlock*[T](ctx: ECB[T]): int =
  mixin sizeBlock
  sizeBlock(ctx.cipher)

template sizeKey*[T](ctx: ECB[T]): int =
  mixin sizeKey
  sizeKey(ctx.cipher)

proc init*[T](ctx: var ECB[T], keyBytes: ptr byte) =
  mixin init
  assert(not isNil(keyBytes))
  init(ctx.cipher, keyBytes)
  assert(ctx.sizeBlock <= MaxBlockSize)

proc init*[T](ctx: var ECB[T], key: openarray[byte]) =
  mixin init
  init(ctx.cipher, key)
  assert(ctx.sizeBlock <= MaxBlockSize)

proc clear*[T](ctx: var ECB[T]) {.inline.} =
  burnMem(ctx)

proc encrypt*[T](ctx: var ECB[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable.} =
  mixin encrypt
  assert(not isNil(inp) and not isNil(oup))
  assert(length != 0)

  var blen = uint(ctx.sizeBlock)
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  var tp = cast[ptr UncheckedArray[byte]](addr ctx.tmp[0])

  var i = length
  while i != 0:
    if i < blen:
      copyMem(tp, ip, i)
      ctx.cipher.encrypt(cast[ptr byte](tp), cast[ptr byte](op))
      break
    ctx.cipher.encrypt(cast[ptr byte](ip), cast[ptr byte](op))
    i = i - blen
    ip = cast[ptr UncheckedArray[byte]](cast[uint](ip) + blen)
    op = cast[ptr UncheckedArray[byte]](cast[uint](op) + blen)
  result = length

proc decrypt*[T](ctx: var ECB[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable.} =
  mixin decrypt
  assert(not isNil(inp) and not isNil(oup))
  assert(length != 0)
  assert(length mod uint(ctx.sizeBlock) == 0)

  var blen = uint(ctx.sizeBlock)
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  var i = length
  while i != 0:
    ctx.cipher.decrypt(cast[ptr byte](ip), cast[ptr byte](op))
    i = i - blen
    ip = cast[ptr UncheckedArray[byte]](cast[uint](ip) + blen)
    op = cast[ptr UncheckedArray[byte]](cast[uint](op) + blen)
  result = length

proc encrypt*[T](ctx: var ECB[T], input: openarray[byte],
                 output: var openarray[byte]) {.inline.} =
  assert(len(input) <= len(output))
  assert(len(input) > 0)
  encrypt(ctx, unsafeAddr input[0], addr output[0], uint(len(input)))

proc decrypt*[T](ctx: var ECB[T], input: openarray[byte],
                 output: var openarray[byte]) {.inline.} =
  assert(len(input) <= len(output))
  assert(len(input) > 0)
  decrypt(ctx, unsafeAddr input[0], addr output[0], uint(len(input)))

## CBC (Cipher Block Chaining) Mode

template sizeBlock*[T](ctx: CBC[T]): int =
  mixin sizeBlock
  sizeBlock(ctx.cipher)

template sizeKey*[T](ctx: CBC[T]): int =
  mixin sizeKey
  sizeKey(ctx.cipher)

proc init*[T](ctx: var CBC[T], keyBytes: ptr byte, iv: ptr byte) =
  mixin init
  assert(not isNil(keyBytes) and not isNil(iv))
  init(ctx.cipher, keyBytes)
  assert(ctx.sizeBlock <= MaxBlockSize)
  copyMem(addr ctx.iv[0], iv, ctx.sizeBlock)

proc init*[T](ctx: var CBC[T], key: openarray[byte], iv: openarray[byte]) =
  mixin init
  init(ctx.cipher, key)
  assert(len(iv) >= ctx.sizeBlock)
  assert(ctx.sizeBlock <= MaxBlockSize)
  copyMem(addr ctx.iv[0], unsafeAddr iv[0], ctx.sizeBlock)

proc clear*[T](ctx: var CBC[T]) {.inline.} =
  burnMem(ctx)

proc encrypt*[T](ctx: var CBC[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable.} =
  mixin encrypt
  assert(not isNil(inp) and not isNil(oup))
  assert(length != 0)

  var blen = uint(ctx.sizeBlock)
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  var cp = cast[ptr UncheckedArray[byte]](addr ctx.iv[0])

  var i = length
  while i != 0:
    var n = 0'u
    while (n < blen) and (n < length):
      op[n] = ip[n] xor cp[n]
      inc(n)
    while n < blen:
      op[n] = cp[n]
      inc(n)
    ctx.cipher.encrypt(cast[ptr byte](op), cast[ptr byte](op))
    cp = op
    if i < blen:
      break
    i = i - blen
    ip = cast[ptr UncheckedArray[byte]](cast[uint](ip) + blen)
    op = cast[ptr UncheckedArray[byte]](cast[uint](op) + blen)
  copyMem(addr ctx.iv[0], cp, blen)
  result = length

proc decrypt*[T](ctx: var CBC[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable.} =
  mixin decrypt
  assert(not isNil(inp) and not isNil(oup))
  assert(length != 0)

  let blen = uint(ctx.sizeBlock)
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  var tp = cast[ptr UncheckedArray[byte]](addr ctx.tmp[0])
  var cp = cast[ptr UncheckedArray[byte]](addr ctx.iv[0])

  var i = length
  while i != 0:
    var n = 0'u
    ctx.cipher.decrypt(cast[ptr byte](ip), cast[ptr byte](tp))
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
    ip = cast[ptr UncheckedArray[byte]](cast[uint](ip) + blen)
    op = cast[ptr UncheckedArray[byte]](cast[uint](op) + blen)
  result = length

proc encrypt*[T](ctx: var CBC[T], input: openarray[byte],
                 output: var openarray[byte]) {.inline.} =
  assert(len(input) <= len(output))
  assert(len(input) > 0)
  encrypt(ctx, unsafeAddr input[0], addr output[0], uint(len(input)))

proc decrypt*[T](ctx: var CBC[T], input: openarray[byte],
                 output: var openarray[byte]) {.inline.} =
  assert(len(input) <= len(output))
  assert(len(input) > 0)
  decrypt(ctx, unsafeAddr input[0], addr output[0], uint(len(input)))

## CTR (Counter) Mode

template sizeBlock*[T](ctx: CTR[T]): int =
  mixin sizeBlock
  sizeBlock(ctx.cipher)

template sizeKey*[T](ctx: CTR[T]): int =
  mixin sizeKey
  sizeKey(ctx.cipher)

proc inc128(counter: ptr UncheckedArray[byte]) =
  var n = 16'u32
  var c = 1'u32
  while true:
    dec(n)
    c = c + counter[n]
    counter[n] = cast[byte](c)
    c = c shr 8
    if n == 0:
      break

proc inc256(counter: ptr UncheckedArray[byte]) =
  var n = 32'u32
  var c = 1'u32
  while true:
    dec(n)
    c = c + counter[n]
    counter[n] = cast[byte](c)
    c = c shr 8
    if n == 0:
      break

proc init*[T](ctx: var CTR[T], keyBytes: ptr byte, iv: ptr byte) =
  mixin init
  assert(not isNil(keyBytes) and not isNil(iv))
  init(ctx.cipher, keyBytes)
  assert(ctx.sizeBlock <= MaxBlockSize)
  copyMem(addr ctx.iv[0], iv, ctx.sizeBlock)

proc init*[T](ctx: var CTR[T], key: openarray[byte], iv: openarray[byte]) =
  mixin init
  init(ctx.cipher, key)
  assert(len(iv) >= ctx.sizeBlock)
  assert(ctx.sizeBlock <= MaxBlockSize)
  copyMem(addr ctx.iv[0], unsafeAddr iv[0], ctx.sizeBlock)

proc clear*[T](ctx: var CTR[T]) {.inline.} =
  burnMem(ctx)

proc encrypt*[T](ctx: var CTR[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable.} =
  mixin encrypt
  assert(not isNil(inp) and not isNil(oup))
  assert(length != 0)
  assert(ctx.sizeBlock == (128 div 8) or ctx.sizeBlock == (256 div 8))
  var n = ctx.num
  var i = 0'u
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  var cp = cast[ptr UncheckedArray[byte]](addr ctx.iv[0])
  let mask = uint(ctx.sizeBlock)

  while i < length:
    if n == 0:
      ctx.cipher.encrypt(addr ctx.iv[0], addr ctx.ecount[0])
      if ctx.sizeBlock == (128 div 8):
        inc128(cp)
      elif ctx.sizeBlock == (256 div 8):
        inc256(cp)
    op[i] = cast[byte](ip[i] xor ctx.ecount[n])
    inc(i)
    n = (n + 1) mod mask

  ctx.num = uint(n)
  result = ctx.num

proc decrypt*[T](ctx: var CTR[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable, inline.} =
  mixin encrypt
  result = encrypt(ctx, inp, oup, length)

proc encrypt*[T](ctx: var CTR[T], input: openarray[byte],
                 output: var openarray[byte]) {.inline.} =
  assert(len(input) <= len(output))
  assert(len(input) > 0)
  encrypt(ctx, unsafeAddr input[0], addr output[0], uint(len(input)))

proc decrypt*[T](ctx: var CTR[T], input: openarray[byte],
                 output: var openarray[byte]) {.inline.} =
  assert(len(input) <= len(output))
  assert(len(input) > 0)
  decrypt(ctx, unsafeAddr input[0], addr output[0], uint(len(input)))

## OFB (Output Feedback) Mode

template sizeBlock*[T](ctx: OFB[T]): int =
  mixin sizeBlock
  sizeBlock(ctx.cipher)

template sizeKey*[T](ctx: OFB[T]): int =
  mixin sizeKey
  sizeKey(ctx.cipher)

proc init*[T](ctx: var OFB[T], keyBytes: ptr byte, iv: ptr byte) =
  mixin init
  assert(not isNil(keyBytes) and not isNil(iv))
  init(ctx.cipher, keyBytes)
  assert(ctx.sizeBlock <= MaxBlockSize)
  copyMem(addr ctx.iv[0], iv, ctx.sizeBlock)

proc init*[T](ctx: var OFB[T], key: openarray[byte], iv: openarray[byte]) =
  mixin init
  init(ctx.cipher, key)
  assert(len(iv) == ctx.sizeBlock)
  assert(ctx.sizeBlock <= MaxBlockSize)
  copyMem(addr ctx.iv[0], unsafeAddr iv[0], ctx.sizeBlock)

proc clear*[T](ctx: var OFB[T]) {.inline.} =
  burnMem(ctx)

proc encrypt*[T](ctx: var OFB[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable.} =
  mixin encrypt
  assert(not isNil(inp) and not isNil(oup))
  assert(length != 0)
  assert(ctx.sizeBlock == (128 div 8) or ctx.sizeBlock == (256 div 8))
  var n = 0
  var i = 0'u
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  var cp = cast[ptr UncheckedArray[byte]](addr ctx.iv[0])
  let mask = ctx.sizeBlock

  while i < length:
    if n == 0:
      ctx.cipher.encrypt(cast[ptr byte](cp), cast[ptr byte](cp))
    op[i] = ip[i] xor cp[n]
    inc(i)
    n = (n + 1) mod mask
  result = uint(n)

proc decrypt*[T](ctx: var OFB[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable, inline.} =
  mixin encrypt
  result = encrypt(ctx, inp, oup, length)

proc encrypt*[T](ctx: var OFB[T], input: openarray[byte],
                 output: var openarray[byte]) {.inline.} =
  assert(len(input) <= len(output))
  assert(len(input) > 0)
  encrypt(ctx, unsafeAddr input[0], addr output[0], uint(len(input)))

proc decrypt*[T](ctx: var OFB[T], input: openarray[byte],
                 output: var openarray[byte]) {.inline.} =
  assert(len(input) <= len(output))
  assert(len(input) > 0)
  decrypt(ctx, unsafeAddr input[0], addr output[0], uint(len(input)))

## CFB (Cipher Feedback) Mode

template sizeBlock*[T](ctx: CFB[T]): int =
  mixin sizeBlock
  sizeBlock(ctx.cipher)

template sizeKey*[T](ctx: CFB[T]): int =
  mixin sizeKey
  sizeKey(ctx.cipher)

proc init*[T](ctx: var CFB[T], keyBytes: ptr byte, iv: ptr byte) =
  mixin init
  assert(not isNil(keyBytes) and not isNil(iv))
  init(ctx.cipher, keyBytes)
  doAssert(ctx.sizeBlock <= MaxBlockSize)
  copyMem(addr ctx.iv[0], iv, ctx.sizeBlock)

proc init*[T](ctx: var CFB[T], key: openarray[byte], iv: openarray[byte]) =
  mixin init
  init(ctx.cipher, key)
  assert(len(iv) == ctx.sizeBlock)
  assert(ctx.sizeBlock <= MaxBlockSize)
  copyMem(addr ctx.iv[0], unsafeAddr iv[0], ctx.sizeBlock)

proc clear*[T](ctx: var CFB[T]) {.inline.} =
  burnMem(ctx)

proc encrypt*[T](ctx: var CFB[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable.} =
  mixin encrypt
  assert(not isNil(inp) and not isNil(oup))
  assert(length != 0)
  var n = 0
  var i = 0'u
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  var cp = cast[ptr UncheckedArray[byte]](addr ctx.iv[0])
  let mask = ctx.sizeBlock

  while i < length:
    if n == 0:
      ctx.cipher.encrypt(cast[ptr byte](cp), cast[ptr byte](cp))
    cp[n] = cp[n] xor ip[i]
    op[i] = cp[n]
    inc(i)
    n = (n + 1) mod mask
  result = uint(n)

proc decrypt*[T](ctx: var CFB[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable, inline.} =
  mixin encrypt
  assert(not isNil(inp) and not isNil(oup))
  assert(length != 0)
  var n = 0
  var i = 0'u
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  var cp = cast[ptr UncheckedArray[byte]](addr ctx.iv[0])
  let mask = ctx.sizeBlock

  while i < length:
    if n == 0:
      ctx.cipher.encrypt(cast[ptr byte](cp), cast[ptr byte](cp))
    let c = ip[i]
    op[i] = cp[n] xor c
    cp[n] = c
    inc(i)
    n = (n + 1) mod mask
  result = uint(n)

proc encrypt*[T](ctx: var CFB[T], input: openarray[byte],
                 output: var openarray[byte]) =
  assert(len(input) <= len(output))
  assert(len(input) > 0)
  encrypt(ctx, unsafeAddr input[0], addr output[0], uint(len(input)))

proc decrypt*[T](ctx: var CFB[T], input: openarray[byte],
                 output: var openarray[byte]) =
  assert(len(input) <= len(output))
  assert(len(input) > 0)
  decrypt(ctx, unsafeAddr input[0], addr output[0], uint(len(input)))
