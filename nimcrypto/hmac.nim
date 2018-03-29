#
#
#                    NimCrypto
#        (c) Copyright 2016 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements HMAC (Keyed-Hashing for Message Authentication)
## [http://www.ietf.org/rfc/rfc2104.txt].

import hash, utils
from sha2 import Sha2Context
from ripemd import RipemdContext
from keccak import KeccakContext

{.deadCodeElim:on.}

const
  MaxHmacBlockSize = 256

type
  HMAC*[HashType] = object
    mdctx: HashType
    opadctx: HashType

template sizeBlock*(h: HMAC[Sha2Context]): uint =
  uint(h.HashType.bsize)

template sizeBlock*(h: HMAC[RipemdContext]): uint =
  64'u

template sizeBlock*(h: HMAC[KeccakContext]): uint =
  when h.HashType.kind == Keccak or h.HashType.kind == Sha3:
    when h.HashType.bits == 224:
      144'u
    elif h.HashType.bits == 256:
      136'u
    elif h.HashType.bits == 384:
      104'u
    elif h.HashType.bits == 512:
      72'u
    else:
      {.fatal: "Choosen hash primitive is not yet supported!".}
  else:
    {.fatal: "Choosen hash primitive is not yet supported!".}

template sizeDigest*(h: HMAC[Sha2Context]): uint = Sha2Context.bits
template sizeDigest*(h: HMAC[RipemdContext]): uint = RipemdContext.bits
template sizeDigest*(h: HMAC[KeccakContext]): uint = KeccakContext.bits

proc init*[T](hmctx: var HMAC[T], key: ptr byte, ulen: uint) =
  mixin init, update, finish
  var k: array[MaxHmacBlockSize, byte]
  var ipad: array[MaxHmacBlockSize, byte]
  var opad: array[MaxHmacBlockSize, byte]
  const sizeBlock = hmctx.sizeBlock

  hmctx.mdctx = T()
  hmctx.opadctx = T()
  init(hmctx.opadctx)

  if not isNil(key):
    if ulen > sizeBlock:
      init(hmctx.mdctx)
      update(hmctx.mdctx, key, ulen)
      discard finish(hmctx.mdctx, addr k[0], sizeBlock)
    else:
      if ulen > 0'u: copyMem(addr k[0], key, ulen)

  var i = 0'u
  while i < sizeBlock:
    opad[i] = 0x5C'u8 xor k[i]
    ipad[i] = 0x36'u8 xor k[i]
    inc(i)

  init(hmctx.mdctx)
  update(hmctx.mdctx, addr ipad[0], sizeBlock)
  update(hmctx.opadctx, addr opad[0], sizeBlock)

proc init*[T](hmctx: var HMAC[T], key: openarray[byte]) {.inline.} =
  assert(len(key) > 0)
  init(hmctx, unsafeAddr key[0], uint(len(key)))

proc clear*[T](hmctx: var HMAC[T]) =
  burnMem(hmctx)

proc update*(hmctx: var HMAC, data: ptr byte, ulen: uint) =
  mixin update
  update(hmctx.mdctx, data, ulen)

proc update*[T: bchar](hmctx: var HMAC, data: openarray[T]) {.inline.} =
  if len(data) == 0:
    update(hmctx, nil, 0'u)
  else:
    update(hmctx, cast[ptr byte](unsafeAddr data[0]), uint(len(data)))

proc finish*(hmctx: var HMAC, data: ptr byte, ulen: uint): uint =
  mixin update, finish
  var buffer: array[hmctx.HashType.bits div 8, byte]
  let size = finish(hmctx.mdctx, addr buffer[0],
                    uint(hmctx.HashType.bits div 8))
  hmctx.opadctx.update(addr buffer[0], size)
  result = hmctx.opadctx.finish(data, ulen)

proc finish*[T: bchar](hmctx: var HMAC, data: var openarray[T]) {.inline.} =
  assert(len(data) >= hmctx.sizeDigest)
  finish(hmctx, cast[ptr byte](addr data[0]), uint(len(data)))

proc finish*(hmctx: var HMAC): MDigest[hmctx.HashType.bits] =
  discard finish(hmctx, cast[ptr byte](addr result.data[0]),
                 uint(len(result.data)))

proc hmac*(HashType: typedesc, key: ptr byte, klen: uint,
           data: ptr byte, ulen: uint): MDigest[HashType.bits] =
  var ctx: HMAC[HashType]
  ctx.init(key, klen)
  ctx.update(data, ulen)
  result = ctx.finish()
  ctx.clear()

proc hmac*[A, B](HashType: typedesc, key: openarray[A],
                 data: openarray[B],
                 ostart: int = 0, ofinish: int = -1): MDigest[HashType.bits] =
  var ctx: HMAC[HashType]
  let so = if ostart < 0: (len(data) + ostart) else: ostart
  let eo = if ofinish < 0: (len(data) + ofinish) else: ofinish
  let length = (eo - so + 1) * sizeof(B)
  if len(key) == 0:
    ctx.init(nil, 0)
  else:
    ctx.init(cast[ptr byte](unsafeAddr key[0]), uint(sizeof(A) * len(key)))
  if length <= 0:
    result = ctx.finish()
  else:
    ctx.update(cast[ptr byte](unsafeAddr data[so]), uint(length))
    result = ctx.finish()
  ctx.clear()
