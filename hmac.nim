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
  uint(Sha2Context.bsize)

template sizeBlock*(h: HMAC[RipemdContext]): uint =
  64'u

template sizeBlock*(h: HMAC[KeccakContext]): uint =
  if KeccakContext.kind == Keccak or KeccakContext.kind == Sha3:
    when KeccakContext.bits == 224:
      144'u
    elif KeccakContext.bits == 256:
      136'u
    elif KeccakContext.bits == 384:
      104'u
    elif KeccakContext.bits == 512:
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
  # var sizeBlock: uint

  # when (T is ripemd128) or (T is ripemd160):
  #   sizeBlock = 64'u
  # elif (T is ripemd256) or (T is ripemd320):
  #   sizeBlock = 64'u
  # elif (T is sha224) or (T is sha256):
  #   sizeBlock = 64'u
  # elif (T is sha384) or (T is sha512):
  #   sizeBlock = 128'u
  # elif (T is sha512_224) or (T is sha512_256):
  #   sizeBlock = 128'u
  # elif (T is sha3_224) or (T is keccak224):
  #   sizeBlock = 144'u
  # elif (T is sha3_256) or (T is keccak256):
  #   sizeBlock = 136'u
  # elif (T is sha3_384) or (T is keccak384):
  #   sizeBlock = 104'u
  # elif (T is sha3_512) or (T is keccak512):
  #   sizeBlock = 72'u
  # else:
  #   {.fatal: "Choosen hash primitive is not yet supported!".}

  hmctx.mdctx = T()
  hmctx.opadctx = T()
  init(hmctx.opadctx)

  if not isNil(key):
    # hmctx.sizeBlock = sizeBlock
    # hmctx.sizeDigest = hmctx.opadctx.sizeDigest

    if ulen > hmctx.sizeBlock:
      init(hmctx.mdctx)
      update(hmctx.mdctx, key, ulen)
      discard finish(hmctx.mdctx, addr k[0], hmctx.sizeBlock)
    else:
      if ulen > 0'u: copyMem(addr k[0], key, ulen)

  var i = 0'u
  while i < hmctx.sizeBlock:
    opad[i] = 0x5C'u8 xor k[i]
    ipad[i] = 0x36'u8 xor k[i]
    inc(i)

  init(hmctx.mdctx)
  update(hmctx.mdctx, addr ipad[0], hmctx.sizeBlock)
  update(hmctx.opadctx, addr opad[0], hmctx.sizeBlock)

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
