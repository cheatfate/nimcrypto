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

type
  Digests128* = ripemd128
  Digests160* = ripemd160
  Digests224* = sha224 | sha512_224 | sha3_224 | keccak224
  Digests256* = ripemd256 | keccak256 | sha256 | sha3_256 | sha512_256
  Digests320* = ripemd320
  Digests384* = sha384 | keccak384 | sha3_384
  Digests512* = sha512 | keccak512 | sha3_512

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

template finishImpl(a, c, d, e: untyped) =
  mixin update
  mixin finish
  var buffer: array[(c), uint8]
  let size = finish((a).mdctx, addr buffer[0], uint((c)))
  update((a).opadctx, addr buffer[0], size)
  result = finish((a).opadctx, (d), (e))

proc finish*[T: Digests128](hmctx: var HMAC[T], data: ptr uint8, ulen: uint): MDigest[128] =
  finishImpl(hmctx, 128 div 8, data, ulen)

proc finish*[T: Digests160](hmctx: var HMAC[T], data: ptr uint8, ulen: uint): MDigest[160] =
  finishImpl(hmctx, 160 div 8, data, ulen)

proc finish*[T: Digests224](hmctx: var HMAC[T], data: ptr uint8, ulen: uint): MDigest[224] =
  finishImpl(hmctx, 224 div 8, data, ulen)

proc finish*[T: Digests256](hmctx: var HMAC[T], data: ptr uint8, ulen: uint): MDigest[256] =
  finishImpl(hmctx, 256 div 8, data, ulen)

proc finish*[T: Digests320](hmctx: var HMAC[T], data: ptr uint8, ulen: uint): MDigest[320] =
  finishImpl(hmctx, 320 div 8, data, ulen)

proc finish*[T: Digests384](hmctx: var HMAC[T], data: ptr uint8, ulen: uint): MDigest[384] =
  finishImpl(hmctx, 384 div 8, data, ulen)

proc finish*[T: Digests512](hmctx: var HMAC[T], data: ptr uint8, ulen: uint): MDigest[512] =
  finishImpl(hmctx, 512 div 8, data, ulen)
