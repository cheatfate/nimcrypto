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
## You can use any of this modes with all the block ciphers of nimcrypto library
##
## GHASH implementation is Nim version of `ghash_ctmul64.c` which is part
## of decent BearSSL project <https://bearssl.org>.
## Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
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
    ## ECB (Electronic Code Book) context object
    cipher: T

  CBC*[T] = object
    ## CBC (Cipher Block Chaining) context object
    cipher: T
    iv: array[MaxBlockBytesSize, byte]
    tmp: array[MaxBlockBytesSize, byte]

  OFB*[T] = object
    ## OFB (Output FeedBack) context object
    cipher: T
    iv: array[MaxBlockBytesSize, byte]

  CFB*[T] = object
    ## CFB (Cipher FeedBack) context object
    cipher: T
    iv: array[MaxBlockBytesSize, byte]

  CTR*[T] = object
    ## CTR (Counter) context object
    cipher: T
    iv: array[MaxBlockBytesSize, byte]
    ecount: array[MaxBlockBytesSize, byte]
    num: uint

  GCM*[T] = object
    ## GCM (Galois/Counter Mode) context object
    cipher: T
    h: array[16, byte]
    y: array[16, byte]
    basectr: array[16, byte]
    buf: array[16, byte]
    aadlen: uint64
    datalen: uint64

## ECB (Electronic Code Book) Mode

template sizeBlock*[T](ctx: ECB[T]): int =
  ## Size of ``ECB[T]`` block in octets (bytes). This value is equal
  ## to cipher ``T`` block size.
  mixin sizeBlock
  sizeBlock(ctx.cipher)

template sizeKey*[T](ctx: ECB[T]): int =
  ## Size of ``ECB[T]`` key in octets (bytes). This value is equal
  ## to cipher ``T`` key size.
  mixin sizeKey
  sizeKey(ctx.cipher)

proc init*[T](ctx: var ECB[T], key: openArray[byte]) {.inline.} =
  ## Initialize ``ECB[T]`` with encryption key ``key``.
  ##
  ## This procedure will not perform any additional padding for encryption
  ## key ``key``.
  ##
  ## Length of ``key`` must be at least ``ECB[T].sizeKey()`` octets (bytes).
  ##
  ## You can see examples of usage ECB mode here ``examples/ecb.nim``.
  mixin init
  assert(ctx.sizeBlock <= MaxBlockSize)
  assert(len(key) >= ctx.sizeKey())
  init(ctx.cipher, key)

proc init*[T](ctx: var ECB[T], key: openArray[char]) {.inline.} =
  ## Initialize ``ECB[T]`` with encryption key ``key``.
  ##
  ## This procedure will not perform any additional padding for encryption
  ## key ``key``.
  ##
  ## Length of ``key`` must be at least ``ECB[T].sizeKey()`` octets (bytes).
  ##
  ## You can see examples of usage ECB mode here ``examples/ecb.nim``.
  init(ctx, key.toOpenArrayByte(0, len(key) - 1))

proc init*[T](ctx: var ECB[T], key: ptr byte) =
  ## Initialize ``ECB[T]`` with encryption key ``key``.
  ##
  ## Note! Size of data pointed by ``key`` must be at least ``ctx.sizeKey``
  ## octets (bytes).
  assert(not isNil(key))
  var p = cast[ptr UncheckedArray[byte]](key)
  init(ctx.cipher, toOpenArray(p, 0, ctx.sizeKey() - 1))

proc clear*[T](ctx: var ECB[T]) {.inline.} =
  ## Clear ``ECB[T]`` context ``ctx``.
  burnMem(ctx)

proc encrypt*[T](ctx: var ECB[T], input: openArray[byte],
                 output: var openArray[byte]) {.inline.} =
  ## Encrypt array of data ``input`` and store encrypted data to array
  ## ``output`` using ``ECB[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array.
  ##
  ## Note, that this procedure do not perform any additional padding, so you
  ## need to do it on your own. Length of ``input`` must be aligned to the
  ## ``ctx.sizeBlock`` value, e.g. ``len(input) mod ctx.sizeBlock == 0``.
  mixin encrypt
  assert(len(input) <= len(output))
  assert(len(input) mod ctx.sizeBlock() == 0)
  var offset = 0
  while offset < len(input):
    ctx.cipher.encrypt(input.toOpenArray(offset, offset + ctx.sizeBlock() - 1),
                       output.toOpenArray(offset, offset + ctx.sizeBlock() - 1))
    offset = offset + ctx.sizeBlock()

proc encrypt*[T](ctx: var ECB[T], input: openArray[char],
                 output: var openArray[char]) {.inline.} =
  ## Encrypt array of data ``input`` and store encrypted data to array
  ## ``output`` using ``ECB[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array.
  ##
  ## Note, that this procedure do not perform any additional padding, so you
  ## need to do it on your own. Length of ``input`` must be aligned to the
  ## ``ctx.sizeBlock`` value, e.g. ``len(input) mod ctx.sizeBlock == 0``.
  encrypt(ctx, input.toOpenArrayByte(0, len(input) - 1),
          output.toOpenArrayByte(0, len(output) - 1))

proc decrypt*[T](ctx: var ECB[T], input: openArray[byte],
                 output: var openArray[byte]) {.inline.} =
  ## Decrypt array of data ``input`` and store decrypted data to array
  ## ``output`` using ``ECB[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array. Length of ``input`` array must not be zero.
  ##
  ## Note, that this procedure do not perform any additional padding, so you
  ## need to do it on your own. Length of ``input`` must be aligned to the
  ## ``ctx.sizeBlock`` value, e.g. ``len(input) mod ctx.sizeBlock == 0``.
  mixin decrypt
  assert(len(input) <= len(output))
  assert(len(input) mod ctx.sizeBlock() == 0)
  var offset = 0
  while offset < len(input):
    ctx.cipher.decrypt(input.toOpenArray(offset, offset + ctx.sizeBlock() - 1),
                       output.toOpenArray(offset, offset + ctx.sizeBlock() - 1))
    offset = offset + ctx.sizeBlock()

proc decrypt*[T](ctx: var ECB[T], input: openArray[char],
                 output: var openArray[char]) {.inline.} =
  ## Decrypt array of data ``input`` and store decrypted data to array
  ## ``output`` using ``ECB[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array. Length of ``input`` array must not be zero.
  ##
  ## Note, that this procedure do not perform any additional padding, so you
  ## need to do it on your own. Length of ``input`` must be aligned to the
  ## ``ctx.sizeBlock`` value, e.g. ``len(input) mod ctx.sizeBlock == 0``.
  decrypt(ctx, input.toOpenArrayByte(0, len(input) - 1),
               output.toOpenArrayByte(0, len(output) - 1))

proc encrypt*[T](ctx: var ECB[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable.} =
  ## Perform ``ECB[T]`` encryption of plain data pointed by ``inp`` of length
  ## ``length`` and store encrypted data to ``oup``. ``oup`` must be able to
  ## hold at least ``length`` octets (bytes) of data.
  ##
  ## Note, that this procedure do not perform any additional padding, so you
  ## need to do it on your own. ``length`` must be aligned to the
  ## ``ctx.sizeBlock`` value, e.g. ``length mod ctx.sizeBlock == 0``.
  ##
  ## Procedure returns number of processed octets (bytes).
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  encrypt(ctx, toOpenArray(ip, 0, int(length - 1)),
               toOpenArray(op, 0, int(length - 1)))
  result = length

proc decrypt*[T](ctx: var ECB[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable.} =
  ## Perform ``ECB[T]`` decryption of encrypted data pointed by ``inp`` of
  ## length ``length`` and store plain data to ``oup``. ``oup`` must be able to
  ## hold at least ``length`` octets (bytes) of data.
  ##
  ## Note, that this procedure do not perform any additional padding, so you
  ## need to do it on your own. ``length`` must be aligned to the
  ## ``ctx.sizeBlock`` value, e.g. ``length mod ctx.sizeBlock == 0``.
  ##
  ## Procedure returns number of processed octets (bytes).
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  decrypt(ctx, toOpenArray(ip, 0, int(length - 1)),
               toOpenArray(op, 0, int(length - 1)))
  result = length

## CBC (Cipher Block Chaining) Mode

template sizeBlock*[T](ctx: CBC[T]): int =
  ## Size of ``CBC[T]`` block in octets (bytes). This value is equal
  ## to cipher ``T`` block size.
  mixin sizeBlock
  sizeBlock(ctx.cipher)

template sizeKey*[T](ctx: CBC[T]): int =
  ## Size of ``CBC[T]`` key in octets (bytes). This value is equal
  ## to cipher ``T`` key size.
  mixin sizeKey
  sizeKey(ctx.cipher)

proc init*[T](ctx: var CBC[T], key: openArray[byte], iv: openArray[byte]) =
  ## Initialize ``CBC[T]`` with encryption key ``key`` and initial vector (IV)
  ## ``iv``.
  ##
  ## This procedure will not perform any additional padding for encryption
  ## key ``key`` and initial vector ``iv``.
  ##
  ## Length of ``key`` must be at least ``ctx.sizeKey()`` octets (bytes).
  ## Length of ``iv`` must be at least ``ctx.sizeBlock()`` octets (bytes)
  ##
  ## You can see examples of usage CBC mode here ``examples/cbc.nim``.
  mixin init
  assert(len(iv) == ctx.sizeBlock())
  assert(len(key) >= ctx.sizeKey())
  assert(ctx.sizeBlock <= MaxBlockSize)
  init(ctx.cipher, key)
  ctx.iv[0 ..< ctx.sizeBlock()] = iv.toOpenArray(0, ctx.sizeBlock() - 1)

proc init*[T](ctx: var CBC[T], key: openArray[char], iv: openArray[char]) =
  ## Initialize ``CBC[T]`` with encryption key ``key`` and initial vector (IV)
  ## ``iv``.
  ##
  ## This procedure will not perform any additional padding for encryption
  ## key ``key`` and initial vector ``iv``.
  ##
  ## Length of ``key`` must be at least ``ctx.sizeKey()`` octets (bytes).
  ## Length of ``iv`` must be at least ``ctx.sizeBlock()`` octets (bytes)
  ##
  ## You can see examples of usage CBC mode here ``examples/cbc.nim``.
  init(ctx, key.toOpenArrayByte(0, len(key) - 1),
            iv.toOpenArrayByte(0, len(iv) - 1))

proc init*[T](ctx: var CBC[T], key: ptr byte, iv: ptr byte) =
  ## Initialize ``CBC[T]`` with encryption key ``key`` and initial vector (IV)
  ## ``iv``.
  ##
  ## Note! Size of encryption key pointed by ``key`` must be at least
  ## ``ctx.sizeKey`` octets (bytes) and size of initial vector ``iv`` must be at
  ## least ``ctx.sizeBlock`` octets (bytes).
  ##
  ## You can see examples of usage CBC mode here ``examples/cbc.nim``.
  assert(not isNil(key) and not isNil(iv))
  var pkey = cast[ptr UncheckedArray[byte]](key)
  var piv = cast[ptr UncheckedArray[byte]](iv)
  init(ctx, toOpenArray(pkey, 0, ctx.sizeKey() - 1),
            toOpenArray(piv, 0, ctx.sizeBlock() - 1))

proc clear*[T](ctx: var CBC[T]) {.inline.} =
  ## Clear ``CBC[T]`` context ``ctx``.
  burnMem(ctx)

proc encrypt*[T](ctx: var CBC[T], input: openArray[byte],
                 output: var openArray[byte]) {.inline.} =
  ## Encrypt array of data ``input`` and store encrypted data to array
  ## ``output`` using ``CBC[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array. Length of ``input`` array must not be zero.
  ##
  ## Note, that this procedure do not perform any additional padding, so you
  ## need to do it on your own. Length of ``input`` must be aligned to the
  ## ``ctx.sizeBlock`` value, e.g. ``len(input) mod ctx.sizeBlock == 0``.
  assert(len(input) <= len(output))
  assert(len(input) mod ctx.sizeBlock() == 0)
  var offset = 0
  while offset < len(input):
    for i in 0 ..< ctx.sizeBlock():
      output[offset + i] = input[offset + i] xor ctx.iv[i]
    ctx.cipher.encrypt(output.toOpenArray(offset, offset + ctx.sizeBlock() - 1),
                       output.toOpenArray(offset, offset + ctx.sizeBlock() - 1))

    ctx.iv[0 ..< ctx.sizeBlock()] =
                        output.toOpenArray(offset, offset + ctx.sizeBlock() - 1)
    offset = offset + ctx.sizeBlock()

proc encrypt*[T](ctx: var CBC[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable.} =
  ## Perform ``CBC[T]`` encryption of plain data pointed by ``inp`` of length
  ## ``length`` and store encrypted data to ``oup``. ``oup`` must be able to
  ## hold at least ``length`` octets (bytes) of data.
  ##
  ## Note, that this procedure do not perform any additional padding, so you
  ## need to do it on your own. ``length`` must be aligned to the
  ## ``ctx.sizeBlock`` value, e.g. ``length mod ctx.sizeBlock == 0``.
  ##
  ## Procedure returns number of processed octets (bytes).
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  encrypt(ctx, toOpenArray(ip, 0, int(length - 1)),
               toOpenArray(op, 0, int(length - 1)))
  result = length

proc encrypt*[T](ctx: var CBC[T], input: openArray[char],
                 output: var openArray[char]) {.inline.} =
  ## Encrypt array of data ``input`` and store encrypted data to array
  ## ``output`` using ``CBC[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array. Length of ``input`` array must not be zero.
  ##
  ## Note, that this procedure do not perform any additional padding, so you
  ## need to do it on your own. Length of ``input`` must be aligned to the
  ## ``ctx.sizeBlock`` value, e.g. ``len(input) mod ctx.sizeBlock == 0``.
  encrypt(ctx, input.toOpenArrayByte(0, len(input) - 1),
               output.toOpenArrayByte(0, len(output) - 1))

proc decrypt*[T](ctx: var CBC[T], input: openArray[byte],
                 output: var openArray[byte]) {.inline.} =
  ## Decrypt array of data ``input`` and store decrypted data to array
  ## ``output`` using ``CBC[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array. Length of ``input`` array must not be zero.
  ##
  ## Note, that this procedure do not perform any additional padding, so you
  ## need to do it on your own. Length of ``input`` must be aligned to the
  ## ``ctx.sizeBlock`` value, e.g. ``len(input) mod ctx.sizeBlock == 0``.
  mixin decrypt
  assert(len(input) <= len(output))
  assert(len(input) mod ctx.sizeBlock() == 0)
  var offset = 0
  while offset < len(input):
    ctx.cipher.decrypt(input.toOpenArray(offset, offset + ctx.sizeBlock() - 1),
                       ctx.tmp)
    for i in 0 ..< ctx.sizeBlock():
      var c = input[offset + i]
      output[offset + i] = ctx.tmp[i] xor ctx.iv[i]
      ctx.iv[i] = c
    offset = offset + ctx.sizeBlock()

proc decrypt*[T](ctx: var CBC[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable.} =
  ## Perform ``CBC[T]`` decryption of encrypted data pointed by ``inp`` of
  ## length ``length`` and store plain data to ``oup``. ``oup`` must be able to
  ## hold at least ``length`` octets (bytes) of data.
  ##
  ## Note, that this procedure do not perform any additional padding, so you
  ## need to do it on your own. ``length`` must be aligned to the
  ## ``ctx.sizeBlock`` value, e.g. ``length mod ctx.sizeBlock == 0``.
  ##
  ## Procedure returns number of processed octets (bytes).
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  decrypt(ctx, toOpenArray(ip, 0, int(length - 1)),
               toOpenArray(op, 0, int(length - 1)))
  result = length

proc decrypt*[T](ctx: var CBC[T], input: openArray[char],
                 output: var openArray[char]) {.inline.} =
  ## Decrypt array of data ``input`` and store decrypted data to array
  ## ``output`` using ``CBC[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array. Length of ``input`` array must not be zero.
  ##
  ## Note, that this procedure do not perform any additional padding, so you
  ## need to do it on your own. Length of ``input`` must be aligned to the
  ## ``ctx.sizeBlock`` value, e.g. ``len(input) mod ctx.sizeBlock == 0``.
  decrypt(ctx, input.toOpenArrayByte(0, len(input) - 1),
               output.toOpenArrayByte(0, len(output) - 1))

## CTR (Counter) Mode

template sizeBlock*[T](ctx: CTR[T]): int =
  ## Size of ``CTR[T]`` block in octets (bytes). This value is equal
  ## to cipher ``T`` block size.
  mixin sizeBlock
  sizeBlock(ctx.cipher)

template sizeKey*[T](ctx: CTR[T]): int =
  ## Size of ``CTR[T]`` key in octets (bytes). This value is equal
  ## to cipher ``T`` key size.
  mixin sizeKey
  sizeKey(ctx.cipher)

proc inc128(counter: var openArray[byte]) =
  var n = 16'u32
  var c = 1'u32
  while true:
    dec(n)
    c = c + counter[n]
    counter[n] = cast[byte](c)
    c = c shr 8
    if n == 0:
      break

proc inc256(counter: var openArray[byte]) =
  var n = 32'u32
  var c = 1'u32
  while true:
    dec(n)
    c = c + counter[n]
    counter[n] = cast[byte](c)
    c = c shr 8
    if n == 0:
      break

proc init*[T](ctx: var CTR[T], key: openArray[byte], iv: openArray[byte]) =
  ## Initialize ``CTR[T]`` with encryption key ``key`` and initial vector (IV)
  ## ``iv``.
  ##
  ## This procedure will not perform any additional padding for encryption
  ## key ``key`` and initial vector ``iv``.
  ##
  ## Length of ``key`` array must be at least ``ctx.sizeKey()`` octets (bytes).
  ## Length of ``iv`` array must be at least ``ctx.sizeBlock()`` octets (bytes).
  ##
  ## You can see examples of usage CTR mode here ``examples/ctr.nim``.
  mixin init
  assert(len(iv) >= ctx.sizeBlock())
  assert(len(key) >= ctx.sizeKey())
  assert(ctx.sizeBlock <= MaxBlockSize)
  init(ctx.cipher, key)
  ctx.iv[0 ..< ctx.sizeBlock()] = iv.toOpenArray(0, ctx.sizeBlock() - 1)

proc init*[T](ctx: var CTR[T], key: ptr byte, iv: ptr byte) =
  ## Initialize ``CTR[T]`` with encryption key ``key`` and initial vector (IV)
  ## ``iv``.
  ##
  ## Note! Size of encryption key pointed by ``key`` must be at least
  ## ``ctx.sizeKey`` octets (bytes) and size of initial vector ``iv`` must be at
  ## least ``ctx.sizeBlock`` octets (bytes).
  ##
  ## You can see examples of usage CTR mode here ``examples/ctr.nim``.
  assert(not isNil(key) and not isNil(iv))
  var pkey = cast[ptr UncheckedArray[byte]](key)
  var piv = cast[ptr UncheckedArray[byte]](iv)
  init(ctx, toOpenArray(pkey, 0, ctx.sizeKey() - 1),
            toOpenArray(piv, 0, ctx.sizeBlock() - 1))

proc init*[T](ctx: var CTR[T], key: openArray[char],
              iv: openArray[char]) {.inline.} =
  ## Initialize ``CTR[T]`` with encryption key ``key`` and initial vector (IV)
  ## ``iv``.
  ##
  ## This procedure will not perform any additional padding for encryption
  ## key ``key`` and initial vector ``iv``.
  ##
  ## Length of ``key`` array must be at least ``ctx.sizeKey()`` octets (bytes).
  ## Length of ``iv`` array must be at least ``ctx.sizeBlock()`` octets (bytes).
  ##
  ## You can see examples of usage CTR mode here ``examples/ctr.nim``.
  init(ctx, key.toOpenArrayByte(0, len(key) - 1),
            iv.toOpenArrayByte(0, len(iv) - 1))

proc clear*[T](ctx: var CTR[T]) {.inline.} =
  ## Clear ``CTR[T]`` context ``ctx``.
  burnMem(ctx)

proc encrypt*[T](ctx: var CTR[T], input: openArray[byte],
                 output: var openArray[byte]) {.inline.} =
  ## Perform ``CTR[T]`` encryption of plain data array ``input`` and store
  ## encrypted data to array ``output`` using ``CTR[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array.
  mixin encrypt
  assert(len(input) <= len(output))
  assert(ctx.sizeBlock == (128 div 8) or ctx.sizeBlock == (256 div 8))

  var offset = 0
  var n = ctx.num
  while offset < len(input):
    if n == 0:
      ctx.cipher.encrypt(ctx.iv, ctx.ecount)
      if ctx.sizeBlock == (128 div 8):
        inc128(ctx.iv)
      elif ctx.sizeBlock == (256 div 8):
        inc256(ctx.iv)
    output[offset] = input[offset] xor ctx.ecount[n]
    inc(offset)
    n = (n + 1) mod ctx.sizeBlock()
  ctx.num = n

proc encrypt*[T](ctx: var CTR[T], input: openArray[char],
                 output: var openArray[char]) {.inline.} =
  ## Perform ``CTR[T]`` encryption of plain data array ``input`` and store
  ## encrypted data to array ``output`` using ``CTR[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array.
  encrypt(ctx, input.toOpenArrayByte(0, len(input) - 1),
               output.toOpenArrayByte(0, len(output) - 1))

proc encrypt*[T](ctx: var CTR[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable.} =
  ## Perform ``CTR[T]`` encryption of plain data pointed by ``inp`` of length
  ## ``length`` and store encrypted data to ``oup``. ``oup`` must be able to
  ## hold at least ``length`` octets (bytes) of data.
  ##
  ## Procedure returns number of processed octets (bytes).
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  encrypt(ctx, toOpenArray(ip, 0, int(length - 1)),
               toOpenArray(op, 0, int(length - 1)))
  result = length

proc decrypt*[T](ctx: var CTR[T], input: openArray[byte],
                 output: var openArray[byte]) {.inline.} =
  ## Perform ``CTR[T]`` decryption of encrypted data array ``input`` and
  ## store decrypted data to array ``output`` using ``CTR[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array.
  encrypt(ctx, input, output)

proc decrypt*[T](ctx: var CTR[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable, inline.} =
  ## Perform ``CTR[T]`` decryption of encrypted data pointed by ``inp`` of
  ## length ``length`` and store decrypted data to ``oup``. ``oup`` must be able
  ## to hold at least ``length`` octets (bytes) of data.
  ##
  ## Procedures returns number of processed octets (bytes).
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  encrypt(ctx, toOpenArray(ip, 0, int(length - 1)),
               toOpenArray(op, 0, int(length - 1)))
  result = length

proc decrypt*[T](ctx: var CTR[T], input: openArray[char],
                 output: var openArray[char]) {.inline.} =
  ## Perform ``CTR[T]`` decryption of encrypted data array ``input`` and
  ## store decrypted data to array ``output`` using ``CTR[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array.
  encrypt(ctx, input.toOpenArrayByte(0, len(input) - 1),
               output.toOpenArrayByte(0, len(output) - 1))

## OFB (Output Feedback) Mode

template sizeBlock*[T](ctx: OFB[T]): int =
  ## Size of ``OFB[T]`` block in octets (bytes). This value is equal
  ## to cipher ``T`` block size.
  mixin sizeBlock
  sizeBlock(ctx.cipher)

template sizeKey*[T](ctx: OFB[T]): int =
  ## Size of ``OFB[T]`` key in octets (bytes). This value is equal
  ## to cipher ``T`` key size.
  mixin sizeKey
  sizeKey(ctx.cipher)

proc init*[T](ctx: var OFB[T], key: openArray[byte], iv: openArray[byte]) =
  ## Initialize ``OFB[T]`` with encryption key ``key`` and initial vector (IV)
  ## ``iv``.
  ##
  ## This procedure will not perform any additional padding for encryption
  ## key ``key`` and initial vector ``iv``.
  ##
  ## Length of ``key`` array must be at least ``ctx.sizeKey()`` octets (bytes).
  ## Length of ``iv`` array must be at least ``ctx.sizeBlock()`` octets (bytes).
  ##
  ## You can see examples of usage OFB mode here ``examples/ofb.nim``.
  mixin init
  assert(len(iv) >= ctx.sizeBlock())
  assert(len(key) >= ctx.sizeKey())
  assert(ctx.sizeBlock <= MaxBlockSize)
  init(ctx.cipher, key)
  ctx.iv[0 ..< ctx.sizeBlock()] = iv.toOpenArray(0, ctx.sizeBlock() - 1)

proc init*[T](ctx: var OFB[T], key: ptr byte, iv: ptr byte) =
  ## Initialize ``OFB[T]`` with encryption key ``key`` and initial vector (IV)
  ## ``iv``.
  ##
  ## Note! Size of encryption key pointed by ``key`` must be at least
  ## ``ctx.sizeKey`` octets (bytes) and size of initial vector ``iv`` must be at
  ## least ``ctx.sizeBlock`` octets (bytes).
  ##
  ## You can see examples of usage OFB mode here ``examples/ofb.nim``.
  assert(not isNil(key) and not isNil(iv))
  var pkey = cast[ptr UncheckedArray[byte]](key)
  var piv = cast[ptr UncheckedArray[byte]](iv)
  init(ctx, toOpenArray(pkey, 0, ctx.sizeKey() - 1),
            toOpenArray(piv, 0, ctx.sizeBlock() - 1))

proc init*[T](ctx: var OFB[T], key: openArray[char], iv: openArray[char]) =
  ## Initialize ``OFB[T]`` with encryption key ``key`` and initial vector (IV)
  ## ``iv``.
  ##
  ## This procedure will not perform any additional padding for encryption
  ## key ``key`` and initial vector ``iv``.
  ##
  ## Length of ``key`` array must be at least ``ctx.sizeKey()`` octets (bytes).
  ## Length of ``iv`` array must be at least ``ctx.sizeBlock()`` octets (bytes).
  ##
  ## You can see examples of usage OFB mode here ``examples/ofb.nim``.
  init(ctx, key.toOpenArrayByte(0, len(key) - 1),
            iv.toOpenArrayByte(0, len(iv) - 1))

proc clear*[T](ctx: var OFB[T]) {.inline.} =
  ## Clear ``OFB[T]`` context ``ctx``.
  burnMem(ctx)

proc encrypt*[T](ctx: var OFB[T], input: openArray[byte],
                 output: var openArray[byte]) {.inline.} =
  ## Encrypt array of data ``input`` and store encrypted data to array
  ## ``output`` using ``OFB[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array.
  mixin encrypt
  assert(len(input) <= len(output))
  var offset = 0
  var n = 0
  while offset < len(input):
    if n == 0:
      ctx.cipher.encrypt(ctx.iv, ctx.iv)
    output[offset] = input[offset] xor ctx.iv[n]
    inc(offset)
    n = (n + 1) mod ctx.sizeBlock()

proc encrypt*[T](ctx: var OFB[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable.} =
  ## Perform ``OFB[T]`` encryption of plain data pointed by ``inp`` of length
  ## ``length`` and store encrypted data to ``oup``. ``oup`` must be able to
  ## hold at least ``length`` octets (bytes) of data.
  ##
  ## Procedure returns number of processed octets (bytes).
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  encrypt(ctx, toOpenArray(ip, 0, int(length - 1)),
               toOpenArray(op, 0, int(length - 1)))
  result = length

proc encrypt*[T](ctx: var OFB[T], input: openArray[char],
                 output: var openArray[char]) {.inline.} =
  ## Encrypt array of data ``input`` and store encrypted data to array
  ## ``output`` using ``OFB[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array.
  encrypt(ctx, input.toOpenArrayByte(0, len(input) - 1),
               output.toOpenArrayByte(0, len(output) - 1))

proc decrypt*[T](ctx: var OFB[T], input: openArray[byte],
                 output: var openArray[byte]) {.inline.} =
  ## Decrypt array of data ``input`` and store decrypted data to array
  ## ``output`` using ``OFB[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array.
  encrypt(ctx, input, output)

proc decrypt*[T](ctx: var OFB[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable, inline.} =
  ## Perform ``OFB[T]`` decryption of encrypted data pointed by ``inp`` of
  ## length ``length`` and store plain data to ``oup``. ``oup`` must be able to
  ## hold at least ``length`` octets (bytes) of data.
  ##
  ## Procedure returns number of processed octets (bytes).
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  encrypt(ctx, toOpenArray(ip, 0, int(length - 1)),
               toOpenArray(op, 0, int(length - 1)))
  result = length

proc decrypt*[T](ctx: var OFB[T], input: openArray[char],
                 output: var openArray[char]) {.inline.} =
  ## Decrypt array of data ``input`` and store decrypted data to array
  ## ``output`` using ``OFB[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array.
  encrypt(ctx, input.toOpenArrayByte(0, len(input) - 1),
               output.toOpenArrayByte(0, len(output) - 1))

## CFB (Cipher Feedback) Mode

template sizeBlock*[T](ctx: CFB[T]): int =
  ## Size of ``CFB[T]`` block in octets (bytes). This value is equal
  ## to cipher ``T`` block size.
  mixin sizeBlock
  sizeBlock(ctx.cipher)

template sizeKey*[T](ctx: CFB[T]): int =
  ## Size of ``CFB[T]`` key in octets (bytes). This value is equal
  ## to cipher ``T`` key size.
  mixin sizeKey
  sizeKey(ctx.cipher)

proc init*[T](ctx: var CFB[T], key: openArray[byte], iv: openArray[byte]) =
  ## Initialize ``CFB[T]`` with encryption key ``key`` and initial vector (IV)
  ## ``iv``.
  ##
  ## This procedure will not perform any additional padding for encryption
  ## key ``key`` and initial vector ``iv``.
  ##
  ## Length of ``key`` array must be at least ``ctx.sizeKey()`` octets (bytes).
  ## Length of ``iv`` array must be at least ``ctx.sizeBlock()`` octets (bytes).
  ##
  ## You can see examples of usage CFB mode here ``examples/cfb.nim``.
  mixin init
  assert(len(iv) >= ctx.sizeBlock())
  assert(len(key) >= ctx.sizeKey())
  assert(ctx.sizeBlock <= MaxBlockSize)
  init(ctx.cipher, key)
  ctx.iv[0 ..< ctx.sizeBlock()] = iv.toOpenArray(0, ctx.sizeBlock() - 1)

proc init*[T](ctx: var CFB[T], key: ptr byte, iv: ptr byte) =
  ## Initialize ``CFB[T]`` with encryption key ``key`` and initial vector (IV)
  ## ``iv``.
  ##
  ## Note! Size of encryption key pointed by ``key`` must be at least
  ## ``ctx.sizeKey`` octets (bytes) and size of initial vector ``iv`` must be at
  ## least ``ctx.sizeBlock`` octets (bytes).
  ##
  ## You can see examples of usage CFB mode here ``examples/cfb.nim``.
  assert(not isNil(key) and not isNil(iv))
  var pkey = cast[ptr UncheckedArray[byte]](key)
  var piv = cast[ptr UncheckedArray[byte]](iv)
  init(ctx, toOpenArray(pkey, 0, ctx.sizeKey() - 1),
            toOpenArray(piv, 0, ctx.sizeBlock() - 1))

proc init*[T](ctx: var CFB[T], key: openArray[char], iv: openArray[char]) =
  ## Initialize ``CFB[T]`` with encryption key ``key`` and initial vector (IV)
  ## ``iv``.
  ##
  ## This procedure will not perform any additional padding for encryption
  ## key ``key`` and initial vector ``iv``.
  ##
  ## Length of ``key`` array must be at least ``ctx.sizeKey()`` octets (bytes).
  ## Length of ``iv`` array must be at least ``ctx.sizeBlock()`` octets (bytes).
  ##
  ## You can see examples of usage CFB mode here ``examples/cfb.nim``.
  init(ctx, key.toOpenArrayByte(0, len(key) - 1),
            iv.toOpenArrayByte(0, len(iv) - 1))

proc clear*[T](ctx: var CFB[T]) {.inline.} =
  ## Clear ``CFB[T]`` context ``ctx``.
  burnMem(ctx)

proc encrypt*[T](ctx: var CFB[T], input: openArray[byte],
                 output: var openArray[byte]) {.inline.} =
  ## Encrypt array of data ``input`` and store encrypted data to array
  ## ``output`` using ``CFB[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array. Length of ``input`` array must not be zero.
  mixin encrypt
  assert(len(input) <= len(output))
  var offset = 0
  var n = 0
  while offset < len(input):
    if n == 0:
      ctx.cipher.encrypt(ctx.iv, ctx.iv)
    ctx.iv[n] = ctx.iv[n] xor input[offset]
    output[offset] = ctx.iv[n]
    inc(offset)
    n = (n + 1) mod ctx.sizeBlock()

proc encrypt*[T](ctx: var CFB[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable.} =
  ## Perform ``CFB[T]`` encryption of plain data pointed by ``inp`` of length
  ## ``length`` and store encrypted data to ``oup``. ``oup`` must be able to
  ## hold at least ``length`` octets (bytes) of data.
  ##
  ## Procedure returns number of processed octets (bytes).
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  encrypt(ctx, toOpenArray(ip, 0, int(length - 1)),
               toOpenArray(op, 0, int(length - 1)))
  result = length

proc encrypt*[T](ctx: var CFB[T], input: openArray[char],
                 output: var openArray[char]) {.inline.} =
  ## Encrypt array of data ``input`` and store encrypted data to array
  ## ``output`` using ``CFB[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array. Length of ``input`` array must not be zero.
  encrypt(ctx, input.toOpenArrayByte(0, len(input) - 1),
               output.toOpenArrayByte(0, len(output) - 1))

proc decrypt*[T](ctx: var CFB[T], input: openArray[byte],
                 output: var openArray[byte]) =
  ## Decrypt array of data ``input`` and store decrypted data to array
  ## ``output`` using ``CFB[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array. Length of ``input`` array must not be zero.
  mixin encrypt
  assert(len(input) <= len(output))
  var n = 0
  var offset = 0
  while offset < len(input):
    if n == 0:
      ctx.cipher.encrypt(ctx.iv, ctx.iv)
    let c = input[offset]
    output[offset] = ctx.iv[n] xor c
    ctx.iv[n] = c
    inc(offset)
    n = (n + 1) mod ctx.sizeBlock()

proc decrypt*[T](ctx: var CFB[T], inp: ptr byte, oup: ptr byte,
                 length: uint): uint {.discardable.} =
  ## Perform ``CFB[T]`` decryption of encrypted data pointed by ``inp`` of
  ## length ``length`` and store plain data to ``oup``. ``oup`` must be able to
  ## hold at least ``length`` octets (bytes) of data.
  ##
  ## Procedure returns number of processed octets (bytes).
  var ip = cast[ptr UncheckedArray[byte]](inp)
  var op = cast[ptr UncheckedArray[byte]](oup)
  decrypt(ctx, toOpenArray(ip, 0, int(length - 1)),
               toOpenArray(op, 0, int(length - 1)))
  result = length

proc decrypt*[T](ctx: var CFB[T], input: openArray[char],
                 output: var openArray[char]) =
  ## Decrypt array of data ``input`` and store decrypted data to array
  ## ``output`` using ``CFB[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` array must be less or equal to length of
  ## ``output`` array. Length of ``input`` array must not be zero.
  decrypt(ctx, input.toOpenArrayByte(0, len(input) - 1),
               output.toOpenArrayByte(0, len(output) - 1))

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

proc ghash(y: var openArray[byte], h: openArray[byte],
           data: openArray[byte]) =
  var  y0, y1, h0, h1, h2, h0r, h1r, h2r: uint64

  y1 = beLoad64(y, 0)
  y0 = beLoad64(y, 8)
  h1 = beLoad64(h, 0)
  h0 = beLoad64(h, 8)
  h0r = rev64(h0)
  h1r = rev64(h1)
  h2 = h0 xor h1
  h2r = h0r xor h1r

  var length = len(data)
  var offset = 0
  while length > 0:
    var tmp: array[16, byte]
    var y0r, y1r, y2, y2r: uint64
    var z0, z1, z2, z0h, z1h, z2h, v0, v1, v2, v3: uint64

    if length >= 16:
      y1 = y1 xor beLoad64(data, offset)
      y0 = y0 xor beLoad64(data, offset + 8)
      dec(length, 16)
      inc(offset, 16)
    else:
      tmp[0 ..< length] = data.toOpenArray(offset, offset + length - 1)
      y1 = y1 xor beLoad64(tmp, 0)
      y0 = y0 xor beLoad64(tmp, 8)
      length = 0

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

  beStore64(y, 0, y1)
  beStore64(y, 8, y0)

template sizeBlock*[T](ctx: GCM[T]): int =
  ## Size of ``GCM[T]`` block in octets (bytes). This value is equal
  ## to cipher ``T`` block size.
  mixin sizeBlock
  sizeBlock(ctx.cipher)

template sizeKey*[T](ctx: GCM[T]): int =
  ## Size of ``GCM[T]`` key in octets (bytes). This value is equal
  ## to cipher ``T`` key size.
  mixin sizeKey
  sizeKey(ctx.cipher)

proc init*[T](ctx: var GCM[T], key: openArray[byte], iv: openArray[byte],
              aad: openArray[byte]) =
  ## Initialize ``GCM[T]`` with encryption key ``key``, initial vector (IV)
  ## ``iv`` and additional authentication data (AAD) ``aad``.
  ##
  ## Size of ``key`` must be at least ``ctx.sizeKey()`` octets (bytes).
  ## Size of cipher ``T`` block must be 128 bits (16 bytes).
  ##
  ## You can see examples of usage GCM mode here ``examples/gcm.nim``.
  mixin init
  # GCM supports only 128bit block ciphers
  assert(ctx.sizeBlock() == (128 div 8))
  assert(len(key) >= ctx.sizeKey())
  burnMem(ctx)
  ctx.cipher.init(key)
  ctx.cipher.encrypt(ctx.h, ctx.h)
  if len(iv) == 12:
    ctx.y[0 ..< 12] = iv.toOpenArray(0, 11)
    inc128(ctx.y)
  else:
    var tmp: array[16, byte]
    ghash(ctx.y, ctx.h, iv)
    beStore32(tmp, 12, uint32(len(iv) shl 3))
    ghash(ctx.y, ctx.h, tmp.toOpenArray(0, 15))
  ctx.cipher.encrypt(ctx.y, ctx.basectr)
  ctx.aadlen = uint64(len(aad))
  ctx.datalen = 0
  if len(aad) > 0:
    ghash(ctx.buf, ctx.h, aad)

proc encrypt*[T](ctx: var GCM[T], input: openArray[byte],
                 output: var openArray[byte]) =
  ## Encrypt array of data ``input`` and store encrypted data to array
  ## ``output`` using ``GCM[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` must be less or equal to length of
  ## ``output``. Length of ``input`` must not be zero.
  mixin encrypt
  var ectr: array[16, byte]
  assert(len(input) <= len(output))

  var length = len(input)
  var offset = 0
  ctx.datalen += uint64(length)
  while length > 0:
    let uselen = if length < 16: length else: 16
    inc128(ctx.y)
    ctx.cipher.encrypt(ctx.y, ectr)
    for i in 0..<uselen:
      output[offset + i] = ectr[i] xor input[offset + i]
    ghash(ctx.buf, ctx.h, output.toOpenArray(offset, offset + uselen - 1))
    length -= uselen
    offset += uselen

proc decrypt*[T](ctx: var GCM[T], input: openArray[byte],
                 output: var openArray[byte]) =
  ## Decrypt array of data ``input`` and store decrypted data to array
  ## ``output`` using ``GCM[T]`` context ``ctx``.
  ##
  ## Note that length of ``input`` must be less or equal to length of
  ## ``output``. Length of ``input`` must not be zero.
  mixin encrypt
  var ectr: array[16, byte]
  assert(len(input) <= len(output))

  var length = len(input)
  var offset = 0
  ctx.datalen += uint64(length)
  while length > 0:
    let uselen = if length < 16: length else: 16
    inc128(ctx.y)
    ctx.cipher.encrypt(ctx.y, ectr)
    for i in 0..<uselen:
      output[offset + i] = ectr[i] xor input[offset + i]
    ghash(ctx.buf, ctx.h, input.toOpenArray(offset, offset + uselen - 1))
    length -= uselen
    offset += uselen

proc getTag*[T](ctx: var GCM[T], tag: var openArray[byte]) =
  ## Obtain authentication tag from ``GCM[T]`` context ``ctx`` and store it to
  ## ``tag``.
  ##
  ## Note that maximum size of ``tag`` is 128 bits (16 bytes).
  let taglen = len(tag)
  let uselen = if taglen < 16: taglen else: 16
  var workbuf: array[16, byte]
  if taglen > 0:
    copyMem(tag, 0, ctx.basectr, 0, uselen)
  beStore64(workbuf, 0, ctx.aadlen shl 3)
  beStore64(workbuf, 8, ctx.datalen shl 3)
  ghash(ctx.buf, ctx.h, workbuf)
  for i in 0..<uselen:
    tag[i] = tag[i] xor ctx.buf[i]

proc getTag*[T](ctx: var GCM[T]): array[16, byte] {.noinit.} =
  ## Obtain authentication tag from ``GCM[T]`` context ``ctx`` and return it as
  ## result array.
  getTag(ctx, result)

proc clear*[T](ctx: var GCM[T]) {.inline.} =
  ## Clear ``GCM[T]`` context ``ctx``.
  burnMem(ctx)
