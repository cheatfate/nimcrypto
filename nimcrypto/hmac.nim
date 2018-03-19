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

import hash
from sha2 import Sha2Context
from ripemd import RipemdContext
from keccak import KeccakContext

const
  MaxHmacBlockSize = 256

type
  HMAC*[HashType] = object
    # sizeBlock*: uint
    # sizeDigest*: uint
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

proc init*[T](hmctx: var HMAC[T], key: ptr uint8, ulen: uint) =
  mixin init, update, finish
  var k: array[MaxHmacBlockSize, uint8]
  var ipad: array[MaxHmacBlockSize, uint8]
  var opad: array[MaxHmacBlockSize, uint8]
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

proc update*(hmctx: var HMAC, data: ptr uint8, ulen: uint) =
  mixin update
  update(hmctx.mdctx, data, ulen)

proc finish*(hmctx: var HMAC, data: ptr uint8, ulen: uint): uint =
  mixin update, finish
  var buffer: array[hmctx.HashType.bits div 8, uint8]
  let size = finish(hmctx.mdctx, addr buffer[0],
                    uint(hmctx.HashType.bits div 8))
  hmctx.opadctx.update(addr buffer[0], size)
  result = hmctx.opadctx.finish(data, ulen)

proc finish*(hmctx: var HMAC): MDigest[hmctx.HashType.bits] =
  discard finish(hmctx, cast[ptr uint8](addr result.data[0]),
                 uint(len(result.data)))

proc hmac*(HashType: typedesc, key: ptr uint8, klen: uint,
           data: ptr uint8, ulen: uint): MDigest[HashType.bits] =
  var ctx: HMAC[HashType]
  ctx.init(key, klen)
  ctx.update(data, ulen)
  result = ctx.finish()

proc hmac*[A, B](HashType: typedesc, key: openarray[A],
                 data: openarray[B],
                 ostart: int = -1, ofinish: int = -1): MDigest[HashType.bits] =
  var ctx: HMAC[HashType]
  assert(len(key) > 0)
  assert(ostart >= -1 and ofinish >= -1)
  let so = if ostart == -1: 0 else: ostart
  let eo = if ofinish == -1: uint(len(data)) else: uint(ofinish - so)
  ctx.init(cast[ptr uint8](unsafeAddr key[0]), uint(sizeof(A) * len(key)))
  assert(uint(so) <= eo)
  if eo == 0:
    result = ctx.finish()
  else:
    ctx.update(cast[ptr uint8](unsafeAddr data[so]), uint(sizeof(B)) * eo)
    result = ctx.finish()
