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
## * GCM (Galois/Counter Mode)
##
## Tests made according to official test vectors (Appendix F)
## http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
## GCM tests made according official test vectors (Appendix B)
## https://pdfs.semanticscholar.org/114a/4222c53f1a6879f1a77f1bae2fc0f8f55348.pdf
## and OpenSSL vectors
## https://github.com/majek/openssl/blob/master/crypto/evp/evptests.txt
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

  GCM*[T] = object
    cipher: T
    h: array[16, byte]
    y: array[16, byte]
    basectr: array[16, byte]
    buf: array[16, byte]
    aadlen: uint64
    datalen: uint64

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

proc inc128(counter: var array[16, byte]) =
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

## GCM (Galois Counter Mode)

# GHASH implementation is Nim version of `ghash_ctmul64.c` which is part
# of decent BearSSL project <https://bearssl.org>.
# Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>

proc bmul64(x, y: uint64): uint64 =
  var x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3: uint64
  x0 = x and 0x1111111111111111'u64
  x1 = x and 0x2222222222222222'u64
  x2 = x and 0x4444444444444444'u64
  x3 = x and 0x8888888888888888'u64
  y0 = y and 0x1111111111111111'u64
  y1 = y and 0x2222222222222222'u64
  y2 = y and 0x4444444444444444'u64
  y3 = y and 0x8888888888888888'u64
  z0 = (x0 * y0) xor (x1 * y3) xor (x2 * y2) xor (x3 * y1)
  z1 = (x0 * y1) xor (x1 * y0) xor (x2 * y3) xor (x3 * y2)
  z2 = (x0 * y2) xor (x1 * y1) xor (x2 * y0) xor (x3 * y3)
  z3 = (x0 * y3) xor (x1 * y2) xor (x2 * y1) xor (x3 * y0)
  z0 = z0 and 0x1111111111111111'u64
  z1 = z1 and 0x2222222222222222'u64
  z2 = z2 and 0x4444444444444444'u64
  z3 = z3 and 0x8888888888888888'u64
  result = z0 or z1 or z2 or z3

template RMS(x, m, s) =
  x = ((x and uint64(m)) shl (s)) or ((x shr (s)) and uint64(m))

proc rev64(x: uint64): uint64 =
  var xx = x
  RMS(xx, 0x5555555555555555'u64, 1)
  RMS(xx, 0x3333333333333333'u64, 2)
  RMS(xx, 0x0F0F0F0F0F0F0F0F'u64, 4)
  RMS(xx, 0x00FF00FF00FF00FF'u64, 8)
  RMS(xx, 0x0000FFFF0000FFFF'u64, 16)
  result = (xx shl 32) or (xx shr 32)

proc ghash(y: var openarray[byte], h: openarray[byte],
           data: ptr byte, size: int) =
  var
    y0, y1, h0, h1, h2, h0r, h1r, h2r: uint64
    buf: ptr byte

  y1 = EGETU64(addr y[0], 0)
  y0 = EGETU64(addr y[0], 8)
  h1 = EGETU64(unsafeAddr h[0], 0)
  h0 = EGETU64(unsafeAddr h[0], 8)
  h0r = rev64(h0)
  h1r = rev64(h1)
  h2 = h0 xor h1
  h2r = h0r xor h1r

  var length = size
  buf = data
  while length > 0:
    var tmp: array[16, byte]
    var src: ptr byte
    var y0r, y1r, y2, y2r: uint64
    var z0, z1, z2, z0h, z1h, z2h, v0, v1, v2, v3: uint64

    if length >= 16:
      src = buf
      buf = cast[ptr byte](cast[uint](buf) + 16)
      length -= 16
    else:
      zeroMem(addr tmp[0], 16)
      copyMem(addr tmp[0], buf, length)
      src = addr tmp[0]
      length = 0

    y1 = y1 xor GETU64(src, 0)
    y0 = y0 xor GETU64(src, 8)

    y0r = rev64(y0)
    y1r = rev64(y1)
    y2 = y0 xor y1;
    y2r = y0r xor y1r;

    z0 = bmul64(y0, h0)
    z1 = bmul64(y1, h1)
    z2 = bmul64(y2, h2)
    z0h = bmul64(y0r, h0r)
    z1h = bmul64(y1r, h1r)
    z2h = bmul64(y2r, h2r)
    z2 = z2 xor (z0 xor z1)
    z2h = z2h xor (z0h xor z1h)
    z0h = rev64(z0h) shr 1
    z1h = rev64(z1h) shr 1
    z2h = rev64(z2h) shr 1

    v0 = z0
    v1 = z0h xor z2
    v2 = z1 xor z2h
    v3 = z1h

    v3 = (v3 shl 1) or (v2 shr 63)
    v2 = (v2 shl 1) or (v1 shr 63)
    v1 = (v1 shl 1) or (v0 shr 63)
    v0 = (v0 shl 1)

    v2 = v2 xor (v0 xor (v0 shr 1) xor (v0 shr 2) xor (v0 shr 7))
    v1 = v1 xor ((v0 shl 63) xor (v0 shl 62) xor (v0 shl 57))
    v3 = v3 xor (v1 xor (v1 shr 1) xor (v1 shr 2) xor (v1 shr 7))
    v2 = v2 xor ((v1 shl 63) xor (v1 shl 62) xor (v1 shl 57))

    y0 = v2
    y1 = v3

  EPUTU64(addr y, 0, y1)
  EPUTU64(addr y, 8, y0)

template sizeBlock*[T](ctx: GCM[T]): int =
  mixin sizeBlock
  sizeBlock(ctx.cipher)

template sizeKey*[T](ctx: GCM[T]): int =
  mixin sizeKey
  sizeKey(ctx.cipher)

proc init*[T](ctx: var GCM[T], key: openarray[byte], iv: openarray[byte],
              aad: openarray[byte]) =
  mixin init
  # GCM supports only 128bit block ciphers
  assert(ctx.sizeBlock == 16)
  assert(len(key) == ctx.sizeKey)
  burnMem(ctx)
  ctx.cipher.init(key)
  ctx.cipher.encrypt(ctx.h, ctx.h)
  if len(iv) == 12:
    copyMem(addr ctx.y[0], unsafeAddr iv[0], 12)
    inc128(ctx.y)
  else:
    var tmp: array[16, byte]
    ghash(ctx.y, ctx.h, unsafeAddr iv[0], len(iv))
    EPUTU32(addr tmp[0], 12, len(iv) shl 3)
    ghash(ctx.y, ctx.h, addr tmp[0], 16)
  ctx.cipher.encrypt(ctx.y, ctx.basectr)
  let slen = len(aad)
  ctx.aadlen = uint64(slen)
  ctx.datalen = 0
  if len(aad) > 0:
    ghash(ctx.buf, ctx.h, unsafeAddr aad[0], slen)

proc encrypt*[T](ctx: var GCM[T], input: openarray[byte],
                 output: var openarray[byte]) =
  mixin encrypt
  var ectr: array[16, byte]
  assert(len(input) <= len(output))
  assert(len(input) > 0)
  var length = len(input)
  var offset = 0
  ctx.datalen += uint64(length)
  while length > 0:
    let uselen = if length < 16: length else: 16
    inc128(ctx.y)
    ctx.cipher.encrypt(ctx.y, ectr)
    for i in 0..<uselen:
      output[offset + i] = ectr[i] xor input[offset + i]
    ghash(ctx.buf, ctx.h, addr output[offset], uselen)
    length -= uselen
    offset += uselen

proc decrypt*[T](ctx: var GCM[T], input: openarray[byte],
                 output: var openarray[byte]) =
  mixin encrypt
  var ectr: array[16, byte]
  assert(len(input) <= len(output))
  assert(len(input) > 0)

  var length = len(input)
  var offset = 0
  ctx.datalen += uint64(length)
  while length > 0:
    let uselen = if length < 16: length else: 16
    inc128(ctx.y)
    ctx.cipher.encrypt(ctx.y, ectr)
    for i in 0..<uselen:
      output[offset + i] = ectr[i] xor input[offset + i]
    ghash(ctx.buf, ctx.h, unsafeAddr input[offset], uselen)
    length -= uselen
    offset += uselen

proc getTag*[T](ctx: var GCM[T], tag: var openarray[byte]) =
  let taglen = len(tag)
  let uselen = if taglen < 16: taglen else: 16
  var workbuf: array[16, byte]
  if taglen > 0:
    copyMem(addr tag[0], addr ctx.basectr[0], uselen)
  EPUTU64(addr workbuf[0], 0, ctx.aadlen shl 3)
  EPUTU64(addr workbuf[0], 8, ctx.datalen shl 3)
  ghash(ctx.buf, ctx.h, addr workbuf[0], 16)
  for i in 0..<uselen:
    tag[i] = tag[i] xor ctx.buf[i]

proc getTag*[T](ctx: var GCM[T]): array[16, byte] {.noinit.} =
  getTag(ctx, result)

proc clear*[T](ctx: var GCM[T]) {.inline.} =
  burnMem(ctx)
