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
from sha2 import sha224, sha256, sha384, sha512, sha512_224, sha512_256
from ripemd import ripemd128, ripemd160, ripemd256, ripemd320
from keccak import sha3_224, sha3_256, sha3_384, sha3_512
from keccak import keccak224, keccak256, keccak384, keccak512

const
  MaxHmacBlockSize = 256

type
  HMAC*[T] = object
    sizeBlock: uint
    sizeDigest: uint
    mdctx: T
    opadctx: T

proc init*[T](hmctx: var HMAC[T], key: ptr uint8, ulen: uint) =
  mixin init
  mixin update
  mixin finish
  var k: array[MaxHmacBlockSize, uint8]
  var ipad: array[MaxHmacBlockSize, uint8]
  var opad: array[MaxHmacBlockSize, uint8]
  var sizeBlock: uint

  when (T is ripemd128) or (T is ripemd160):
    sizeBlock = 64'u
  elif (T is ripemd256) or (T is ripemd320):
    sizeBlock = 64'u
  elif (T is sha224) or (T is sha256):
    sizeBlock = 64'u
  elif (T is sha384) or (T is sha512):
    sizeBlock = 128'u
  elif (T is sha512_224) or (T is sha512_256):
    sizeBlock = 128'u
  elif (T is sha3_224) or (T is keccak224):
    sizeBlock = 144'u
  elif (T is sha3_256) or (T is keccak256):
    sizeBlock = 136'u
  elif (T is sha3_384) or (T is keccak384):
    sizeBlock = 104'u
  elif (T is sha3_512) or (T is keccak512):
    sizeBlock = 72'u
  else:
    {.fatal: "Choosen hash primitive is not yet supported!".}

  hmctx.mdctx = T()
  hmctx.opadctx = T()
  init(hmctx.opadctx)

  if not isNil(key):
    hmctx.sizeBlock = sizeBlock
    hmctx.sizeDigest = hmctx.opadctx.sizeDigest

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

proc update*[T](hmctx: var HMAC[T], data: ptr uint8, ulen: uint) =
  mixin update
  update(hmctx.mdctx, data, ulen)

proc finish*[T](hmctx: var HMAC[T], data: ptr uint8, ulen: uint): uint =
  mixin finish
  mixin update
  var buffer: array[MaxMdDigestLength, uint8]
  
  let size = finish(hmctx.mdctx, addr buffer[0], MaxMdDigestLength)
  update(hmctx.opadctx, addr buffer[0], size)
  result = finish(hmctx.opadctx, data, ulen)

proc finish*[T](hmctx: var HMAC[T]): MdDigest =
  mixin finish
  result = MdDigest()
  result.size = finish(hmctx, cast[ptr uint8](addr result.data[0]),
                       MaxMdDigestLength)
