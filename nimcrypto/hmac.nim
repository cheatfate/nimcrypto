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
##
## Module provides two common interfaces for calculating HMAC.
## ``Classic`` method allows to process big chunks of data using limited amount
## of memory, while ``one-line`` method allows you to perform HMAC calculation
## in one line of code.
##
##  .. code-block::nim
##    import nimcrypto
##
##    ## ``Classic`` method of HMAC calculation.
##
##    var stringToHmac = "Hello World!"
##    var stringHmacKey = "AliceKey"
##    let ptrToHmac = cast[ptr byte](addr stringToHmac[0])
##    let ptrHmacKey = cast[ptr byte](addr stringHmacKey[0])
##    let toHmacLen = uint(len(stringToHmac))
##    let hmacKeyLen = uint(len(stringHmacKey))
##
##    # Declare context objects
##    var hctx1, hctx2: HMAC[sha256]
##    # Initalize HMAC[SHA256] contexts with key `AliceKey`.
##    hctx1.init(stringHmacKey)
##    hctx2.init(ptrHmacKey, hmacKeyLen)
##    # Update HMAC[SHA256] context using data `Hello World!` twice.
##    hctx1.update(stringToHmac)
##    hctx1.update(stringToHmac)
##    # Update HMAC[SHA256] context using data `Hello World!` twice.
##    hctx2.update(ptrToHmac, toHmacLen)
##    hctx2.update(ptrToHmac, toHmacLen)
##    # Print HMAC[SHA256] digest.
##    echo $hctx1.finish()
##    echo $hctx2.finish()
##    # Do not forget to clear contexts.
##    hctx1.clear()
##    hctx2.clear()
##
##    ## ``One-line`` method of HMAC calculation.
##
##    # Print HMAC[SHA256] digest of `Hello World!Hello World!` using key
##    # `AliceKey`.
##    echo $sha256.hmac(stringHmacKey, stringToHmac & stringToHmac)
##
##    # Output to stdout must be 3 equal digests:
##    # 18AF7C8586141A47EAAD416C2B356431D001FAFF3B8C98C80AA108DC971B230D
##    # 18AF7C8586141A47EAAD416C2B356431D001FAFF3B8C98C80AA108DC971B230D
##    # 18AF7C8586141A47EAAD416C2B356431D001FAFF3B8C98C80AA108DC971B230D
import hash, utils
from sha2 import Sha2Context
from ripemd import RipemdContext
from keccak import KeccakContext
from blake2 import Blake2Context
from sha import Sha1Context

{.deadCodeElim:on.}

const
  MaxHmacBlockSize = 256

type
  HMAC*[HashType] = object
    ## HMAC context object.
    mdctx: HashType
    opadctx: HashType

template sizeBlock*(h: HMAC[Sha2Context]): uint =
  ## Size of processing block in octets (bytes), while perform HMAC
  ## operation using SHA2 algorithms.
  cast[uint](h.HashType.sizeBlock)

template sizeBlock*(h: HMAC[RipemdContext]): uint =
  ## Size of processing block in octets (bytes), while perform HMAC
  ## operation using RIPEMD algorithms.
  cast[uint](h.HashType.sizeBlock)

template sizeBlock*(h: HMAC[KeccakContext]): uint =
  ## Size of processing block in octets (bytes), while perform HMAC
  ## operation using KECCAK/SHA3/SHAKE algorithms.
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

template sizeBlock*(h: HMAC[Blake2Context]): uint =
  ## Size of processing block in octets (bytes), while perform HMAC
  ## operation using BLAKE2b/BLAKE2s algorithms.
  cast[uint](h.HashType.sizeBlock)

template sizeBlock*(h: HMAC[Sha1Context]): uint =
  ## Size of processing block in octets (bytes), while perform HMAC
  ## operation using SHA1 algorithm.
  cast[uint](h.HashType.sizeBlock)

template sizeDigest*(h: HMAC[Sha2Context]): uint =
  ## Size of HMAC digest in octets (bytes) using SHA2 algorithms.
  cast[uint](h.mdctx.sizeDigest)

template sizeDigest*(h: HMAC[RipemdContext]): uint =
  ## Size of HMAC digest in octets (bytes) using RIPEMD algorithms.
  cast[uint](h.mdctx.sizeDigest)

template sizeDigest*(h: HMAC[KeccakContext]): uint =
  ## Size of HMAC digest in octets (bytes) using KECCAK/SHA3/SHAKE
  ## algorithms.
  cast[uint](h.mdctx.sizeDigest)

template sizeDigest*(h: HMAC[Blake2Context]): uint =
  ## Size of HMAC digest in octets (bytes) using BLAKE2b/BLAKE2s algorithms.
  cast[uint](h.mdctx.sizeDigest)

template sizeDigest*(h: HMAC[Sha1Context]): uint =
  ## Size of HMAC digest in octets (bytes) using SHA1 algorithm.
  cast[uint](h.mdctx.sizeDigest)

proc init*[T](hmctx: var HMAC[T], key: ptr byte, ulen: uint) =
  ## Initialize HMAC context ``hmctx`` with key using ``key`` and size ``ulen``.
  ##
  ## ``key`` can be ``nil``.
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

  for i in 0..<int(sizeBlock):
    opad[i] = 0x5C'u8 xor k[i]
    ipad[i] = 0x36'u8 xor k[i]

  init(hmctx.mdctx)
  update(hmctx.mdctx, addr ipad[0], sizeBlock)
  update(hmctx.opadctx, addr opad[0], sizeBlock)

proc init*[T](hmctx: var HMAC[T], key: openarray[byte]) {.inline.} =
  ## Initialize HMAC context ``hmctx`` with key using ``key`` array.
  ##
  ## ``key`` can be zero-length array.
  if len(key) == 0:
    init(hmctx, nil, 0'u)
  else:
    init(hmctx, unsafeAddr key[0], cast[uint](len(key)))

proc init*[T](hmctx: var HMAC[T], key: openarray[char]) {.inline.} =
  ## Initialize HMAC context ``hmctx`` with key using ``key`` string/array.
  ##
  ## ``key`` can be zero-length array.
  if len(key) == 0:
    init(hmctx, nil, 0'u)
  else:
    init(hmctx, cast[ptr byte](unsafeAddr key[0]), cast[uint](len(key)))

proc clear*(hmctx: var HMAC) =
  ## Clear HMAC context ``hmctx``.
  burnMem(hmctx)

proc update*(hmctx: var HMAC, data: ptr byte, ulen: uint) =
  ## Update HMAC context ``hmctx`` with data pointed by ``data`` and length
  ## ``ulen``. Repeated calls are equivalent to a single call with the
  ## concatenation of all ``data`` arguments.
  ##
  ## ``data`` can be ``nil``, but ``ulen`` must be ``0`` in such case.
  mixin update
  assert((not isNil(data)) or (isNil(data) and ulen == 0'u))
  update(hmctx.mdctx, data, ulen)

proc update*[T: bchar](hmctx: var HMAC, data: openarray[T]) {.inline.} =
  ## Update HMAC context ``hmctx`` with data array ``data``. Repeated calls are
  ## equivalent to a single call with the concatenation of all ``data``
  ## arguments.
  ##
  ## ``data`` can be zero-length array.
  if len(data) == 0:
    update(hmctx, nil, 0'u)
  else:
    update(hmctx, cast[ptr byte](unsafeAddr data[0]), cast[uint](len(data)))

proc finish*(hmctx: var HMAC, data: ptr byte, ulen: uint): uint =
  ## Finalize HMAC context ``hmctx`` and store calculated digest in data pointed
  ## by ``data`` and length ``ulen``. ``data`` must be able to hold result.
  assert((not isNil(data)) or (isNil(data) and ulen == 0'u))
  mixin update, finish
  var buffer: array[hmctx.sizeDigest, byte]
  let size = finish(hmctx.mdctx, addr buffer[0], cast[uint](hmctx.sizeDigest))
  hmctx.opadctx.update(addr buffer[0], size)
  result = hmctx.opadctx.finish(data, ulen)

proc finish*[T: bchar](hmctx: var HMAC,
                       data: var openarray[T]): uint {.inline.} =
  ## Finalize HMAC context ``hmctx`` and store calculated digest in array
  ## ``data``. ``data`` length must be at least ``hmctx.sizeDigest`` octets
  ## (bytes).
  let ulen = cast[uint](len(data))
  assert(ulen >= hmctx.sizeDigest)
  result = finish(hmctx, cast[ptr byte](addr data[0]), ulen)

proc finish*(hmctx: var HMAC): MDigest[hmctx.HashType.bits] =
  ## Finalize HMAC context ``hmctx`` and return calculated digest as ``MDigest``
  ## object.
  discard finish(hmctx, cast[ptr byte](addr result.data[0]),
                 cast[uint](len(result.data)))

proc hmac*(HashType: typedesc, key: ptr byte, klen: uint,
           data: ptr byte, ulen: uint): MDigest[HashType.bits] =
  ## Perform HMAC computation with hash algorithm ``HashType`` using key ``key``
  ## of length ``klen`` on data buffer pointed by ``data`` of length ``ulen``.
  ##
  ##  .. code-block::nim
  ##    import nimcrypto
  ##
  ##    var stringToHmac = "Hello World!"
  ##    var stringHmacKey = "AliceKey"
  ##    let data = cast[ptr byte](addr stringToHmac[0])
  ##    let datalen = uint(len(stringToHmac))
  ##    let key = cast[ptr byte](addr stringHmacKey[0])
  ##    let keylen = uint(len(stringHmacKey))
  ##    # Print HMAC[SHA256](key = "AliceKey", data = "Hello World!")
  ##    echo sha256.hmac(key, keylen, data, datalen)
  ##    # Print HMAC[SHA512](key = "AliceKey", data = "Hello World!")
  ##    echo sha512.hmac(key, keylen, data, datalen)
  ##    # Print HMAC[KECCAK256](key = "AliceKey", data = "Hello World!")
  ##    echo keccak256.hmac(key, keylen, data, datalen)
  ##    # Print HMAC[RIPEMD160](key = "AliceKey", data = "Hello World!")
  ##    echo ripemd160.hmac(key, keylen, data, datalen)
  var ctx: HMAC[HashType]
  ctx.init(key, klen)
  ctx.update(data, ulen)
  result = ctx.finish()
  ctx.clear()

proc hmac*[A, B](HashType: typedesc, key: openarray[A],
                 data: openarray[B],
                 ostart: int = 0, ofinish: int = -1): MDigest[HashType.bits] =
  ## Perform HMAC computation with hash algorithm ``HashType`` using key ``key``
  ## of data ``data``, in slice ``[ostart, ofinish]``, both ``ostart`` and
  ## ``ofinish`` are inclusive.
  ##
  ##  .. code-block::nim
  ##    import nimcrypto
  ##
  ##    var stringToHmac = "Hello World!"
  ##    var stringHmacKey = "AliceKey"
  ##    # Print HMAC[SHA256] digest of whole string `Hello World!` using
  ##    # key `AliceKey`.
  ##    echo sha256.hmac(stringHmacKey, stringToHmac)
  ##    # Print HMAC[SHA256] digest of `Hello` using key `AliceKey`.
  ##    echo sha256.hmac(stringHmacKey, stringToHmac, ofinish = 4)
  ##    # Print HMAC[SHA256] digest of `World!` using key `AliceKey`.
  ##    echo sha256.hmac(stringHmacKey, stringToHmac, ostart = 6)
  ##    # Print HMAC[SHA256] digest of constant `Hello` using constant key
  ##    # `AliceKey`.
  ##    echo sha256.hmac("AliceKey", "Hello")
  ##    # Print HMAC[SHA256] digest of constant `World!` using constant key
  ##    # `AliceKey`
  ##    echo sha256.hmac("AliceKey", "World!")
  var ctx: HMAC[HashType]
  let so = if ostart < 0: (len(data) + ostart) else: ostart
  let eo = if ofinish < 0: (len(data) + ofinish) else: ofinish
  let length = (eo - so + 1) * sizeof(B)
  if len(key) == 0:
    ctx.init(nil, 0)
  else:
    ctx.init(cast[ptr byte](unsafeAddr key[0]),
                            cast[uint](sizeof(A) * len(key)))
  if length <= 0:
    result = ctx.finish()
  else:
    ctx.update(cast[ptr byte](unsafeAddr data[so]), cast[uint](length))
    result = ctx.finish()
  ctx.clear()
