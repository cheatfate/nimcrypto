#
#
#                    NimCrypto
#      (c) Copyright 2016-2024 Eugene Kabanov
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

{.push raises: [].}

import "."/[utils, cpufeatures]
import "."/[sha, ripemd, keccak, blake2, hash]
import "."/sha2/sha2
export sha, sha2, ripemd, keccak, blake2, hash, cpufeatures

template hmacSizeBlock*(h: typedesc): int =
  mixin sizeBlock
  when (h is Sha1Context) or (h is Sha2Context) or (h is RipemdContext) or
       (h is Blake2Context):
    int(h.sizeBlock)
  elif h is KeccakContext:
    when h.kind == Keccak or h.kind == Sha3:
      when h.bits == 224:
        144
      elif h.bits == 256:
        136
      elif h.bits == 384:
        104
      elif h.bits == 512:
        72
      else:
        {.fatal: "Choosen hash primitive is not yet supported!".}
    else:
      {.fatal: "Choosen hash primitive is not yet supported!".}

type
  HMAC*[HashType] = object
    ## HMAC context object.
    mdctx: HashType
    opadctx: HashType
    ipad: array[HashType.hmacSizeBlock, byte]
    opad: array[HashType.hmacSizeBlock, byte]

  Sha2Type =
    sha224 | sha256 | sha384 | sha512 | sha512_224 | sha512_256

template sizeBlock*[T](h: HMAC[T]): uint =
  ## Size of processing block in octets (bytes), while perform HMAC
  ## operation using one of hash algorithms.
  uint(T.hmacSizeBlock())

template sizeDigest*[T](h: HMAC[T]): uint =
  ## Size of HMAC digest in octets (bytes).
  uint(h.mdctx.sizeDigest)

func init*[T, M](hmctx: var HMAC[T], key: openArray[M]) =
  ## Initialize HMAC context ``hmctx`` with key using ``key`` array.
  ##
  ## ``key`` supports ``openArray[byte]`` and ``openArray[char]`` only.
  mixin init, update, finish

  when not((M is byte) or (M is char)):
    {.fatal: "Choosen key type is not supported!".}

  var kpad: array[hmctx.sizeBlock, byte]
  hmctx.mdctx = T()
  hmctx.opadctx = T()
  init(hmctx.opadctx)

  if len(key) > 0:
    if len(key) > int(hmctx.sizeBlock):
      init(hmctx.mdctx)
      update(hmctx.mdctx, key)
      discard finish(hmctx.mdctx, kpad)
    else:
      copyMem(kpad, 0, key, 0, len(key))

  for i in 0 ..< int(hmctx.sizeBlock):
    hmctx.opad[i] = 0x5C'u8 xor kpad[i]
    hmctx.ipad[i] = 0x36'u8 xor kpad[i]

  init(hmctx.mdctx)
  update(hmctx.mdctx, hmctx.ipad)
  update(hmctx.opadctx, hmctx.opad)

func init*[T](hmctx: var HMAC[T], key: ptr byte, keylen: uint) =
  ## Initialize HMAC context ``hmctx`` with key using ``key`` of size
  ## ``keylen``.
  mixin init
  var ptrarr = cast[ptr UncheckedArray[byte]](key)
  init(hmctx, ptrarr.toOpenArray(0, int(keylen) - 1))

func clear*(hmctx: var HMAC) =
  ## Clear HMAC context ``hmctx``.
  when nimvm:
    mixin clear
    hmctx.mdctx.clear()
    hmctx.opadctx.clear()
    for i in 0 ..< len(hmctx.ipad):
      hmctx.ipad[i] = 0x00'u8
      hmctx.opad[i] = 0x00'u8
  else:
    burnMem(hmctx)

func reset*(hmctx: var HMAC) =
  ## Reset HMAC context ``hmctx`` to initial state (state of context, right
  ## after init() call).
  mixin reset, update
  hmctx.mdctx.reset()
  hmctx.opadctx.reset()
  update(hmctx.mdctx, hmctx.ipad)
  update(hmctx.opadctx, hmctx.opad)

func update*[T: bchar](hmctx: var HMAC, data: openArray[T]) {.inline.} =
  ## Update HMAC context ``hmctx`` with data array ``data``. Repeated calls are
  ## equivalent to a single call with the concatenation of all ``data``
  ## arguments.
  ##
  ##  .. code-block::nim
  ##    import nimcrypto
  ##
  ##    ## Perform calculation of HMAC[SHA256] for string
  ##    ## "aaaaaa<1,000,000 times>", using key "AliceKey".
  ##    var ctx: HMAC[sha256]
  ##    ctx.init("AliceKey")
  ##    for i in 0 ..< 1_000_000:
  ##      ctx.update("a")
  ##    echo $ctx.finish()
  ##
  mixin update
  update(hmctx.mdctx, data)

func update*(hmctx: var HMAC, pbytes: ptr byte, nbytes: uint) {.inline.} =
  ## Update HMAC context ``hmctx`` with data pointed by ``pbytes`` of length
  ## ``nbytes``. Repeated calls are equivalent to a single call with the
  ## concatenation of all ``data`` arguments.
  ##
  ##  .. code-block::nim
  ##    import nimcrypto
  ##
  ##    ## Perform calculation of HMAC[SHA256] for string
  ##    ## "aaaaaa<1,000,000 times>", using key "AliceKey".
  ##    var ctx: HMAC[sha256]
  ##    var source = "a"
  ##    ctx.init("AliceKey")
  ##    for i in 0 ..< 1_000_000:
  ##      ctx.update(addr source[0], len(source))
  ##    echo $ctx.finish()
  ##
  if not(isNil(pbytes)) and (nbytes > 0'u):
    var ptrarr = cast[ptr UncheckedArray[byte]](pbytes)
    hmctx.update(ptrarr.toOpenArray(0, int(nbytes) - 1))

func finish*[T: bchar](hmctx: var HMAC,
                       data: var openArray[T]): uint {.inline.} =
  ## Finalize HMAC context ``hmctx`` and store calculated digest to array
  ## ``data``. ``data`` length must be at least ``hmctx.sizeDigest`` octets
  ## (bytes).
  mixin update, finish
  if len(data) >= int(hmctx.sizeDigest):
    var buffer: array[hmctx.sizeDigest, byte]
    discard finish(hmctx.mdctx, buffer)
    hmctx.opadctx.update(buffer)
    hmctx.opadctx.finish(data)
  else:
    0

func finish*(hmctx: var HMAC, pbytes: ptr byte, nbytes: uint): uint {.inline.} =
  ## Finalize HMAC context ``hmctx`` and store calculated digest to address
  ## pointed by ``pbytes`` of length ``nbytes``. ``pbytes`` must be able to
  ## hold at ``hmctx.sizeDigest`` octets (bytes).
  var ptrarr = cast[ptr UncheckedArray[byte]](pbytes)
  hmctx.finish(ptrarr.toOpenArray(0, int(nbytes) - 1))

func finish*(hmctx: var HMAC): MDigest[hmctx.HashType.bits] =
  ## Finalize HMAC context ``hmctx`` and return calculated digest as
  ## ``MDigest`` object.
  var res: MDigest[hmctx.HashType.bits]
  discard finish(hmctx, res.data)
  res

func hmac*[A: bchar, B: bchar](
    HashType: typedesc,
    key: openArray[A],
    data: openArray[B]
): MDigest[HashType.bits] =
  ## Perform HMAC computation with hash algorithm ``HashType`` using key ``key``
  ## of data ``data``.
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
  ##    echo sha256.hmac(stringHmacKey, stringToHmac.toOpenArray(0, 4))
  ##    # Print HMAC[SHA256] digest of `World!` using key `AliceKey`.
  ##    echo sha256.hmac(stringHmacKey, stringToHmac.toOpenArray(6, 11))
  ##    # Print HMAC[SHA256] digest of constant `Hello` using constant key
  ##    # `AliceKey`.
  ##    echo sha256.hmac("AliceKey", "Hello")
  ##    # Print HMAC[SHA256] digest of constant `World!` using constant key
  ##    # `AliceKey`
  ##    echo sha256.hmac("AliceKey", "World!")
  var ctx: HMAC[HashType]
  ctx.init(key)
  ctx.update(data)
  let res = ctx.finish()
  ctx.clear()
  res

func hmac*(
    HashType: typedesc,
    key: ptr byte,
    klen: uint,
    data: ptr byte,
    ulen: uint
): MDigest[HashType.bits] {.inline.} =
  ## Perform HMAC computation with hash algorithm ``HashType`` using key ``key``
  ## of length ``klen`` for data buffer pointed by ``data`` of length ``ulen``.
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
  var
    keyarr = cast[ptr UncheckedArray[byte]](key)
    dataarr = cast[ptr UncheckedArray[byte]](data)
  hmac(HashType, keyarr.toOpenArray(0, int(klen) - 1),
       dataarr.toOpenArray(0, int(ulen) - 1))

## Optimized SHA2 declarations
func init*[T: Sha2Type, M](
    hmctx: var HMAC[T],
    key: openArray[M],
    implementation: Sha2Implementation,
    cpufeatures: set[CpuFeature]
) =
  mixin init, update, finish

  when not((M is byte) or (M is char)):
    {.fatal: "Choosen key type is not supported!".}

  var kpad: array[hmctx.sizeBlock, byte]
  init(hmctx.opadctx, implementation, cpufeatures)

  if len(key) > 0:
    if len(key) > int(hmctx.sizeBlock):
      init(hmctx.mdctx, implementation, cpufeatures)
      update(hmctx.mdctx, key)
      discard finish(hmctx.mdctx, kpad)
    else:
      copyMem(kpad, 0, key, 0, len(key))

  for i in 0 ..< int(hmctx.sizeBlock):
    hmctx.opad[i] = 0x5C'u8 xor kpad[i]
    hmctx.ipad[i] = 0x36'u8 xor kpad[i]

  init(hmctx.mdctx, implementation, cpufeatures)
  update(hmctx.mdctx, hmctx.ipad)
  update(hmctx.opadctx, hmctx.opad)

func init*[T: Sha2Type, M](
    hmctx: var HMAC[T],
    key: openArray[M],
    implementation: Sha2Implementation
) =
  init(hmctx, key, implementation, defaultCpuFeatures)

func init*[T: Sha2Type, M](
    hmctx: var HMAC[T],
    key: openArray[M]
) =
  init(hmctx, key, Sha2Implementation.Auto, defaultCpuFeatures)

func init*[T: Sha2Type](
    hmctx: var HMAC[T],
    key: ptr byte,
    keylen: uint,
    implementation: Sha2Implementation,
    cpufeatures: set[CpuFeature]
) =
  var ptrarr = cast[ptr UncheckedArray[byte]](key)
  init(
    hmctx, ptrarr.toOpenArray(0, int(keylen) - 1), implementation, cpufeatures)

func init*[T: Sha2Type](
    hmctx: var HMAC[T],
    key: ptr byte,
    keylen: uint,
    implementation: Sha2Implementation
) =
  var ptrarr = cast[ptr UncheckedArray[byte]](key)
  init(
    hmctx, ptrarr.toOpenArray(0, int(keylen) - 1), implementation,
    defaultCpuFeatures)

func init*[T: Sha2Type](
    hmctx: var HMAC[T],
    key: ptr byte,
    keylen: uint,
) =
  var ptrarr = cast[ptr UncheckedArray[byte]](key)
  init(
    hmctx, ptrarr.toOpenArray(0, int(keylen) - 1), Sha2Implementation.Auto,
    defaultCpuFeatures)

template declareHmac(DigestType: untyped) =
  func hmac*[A: bchar, B: bchar](
      HashType: typedesc[DigestType],
      key: openArray[A],
      data: openArray[B],
      implementation: Sha2Implementation,
      cpufeatures: set[CpuFeature]
  ): MDigest[HashType.bits] =
    var ctx: HMAC[HashType]
    ctx.init(key, implementation, cpufeatures)
    ctx.update(data)
    let res = ctx.finish()
    ctx.clear()
    res

  func hmac*[A: bchar, B: bchar](
      HashType: typedesc[DigestType],
      key: openArray[A],
      data: openArray[B],
      implementation: Sha2Implementation
  ): MDigest[HashType.bits] =
    hmac(HashType, key, data, implementation, defaultCpuFeatures)

  func hmac*[A: bchar, B: bchar](
      HashType: typedesc[DigestType],
      key: openArray[A],
      data: openArray[B],
  ): MDigest[HashType.bits] =
    hmac(HashType, key, data, Sha2Implementation.Auto, defaultCpuFeatures)

  func hmac*(
      HashType: typedesc[DigestType],
      key: ptr byte,
      klen: uint,
      data: ptr byte,
      ulen: uint,
      implementation: Sha2Implementation,
      cpufeatures: set[CpuFeature]
  ): MDigest[HashType.bits] =
    var
      keyarr = cast[ptr UncheckedArray[byte]](key)
      dataarr = cast[ptr UncheckedArray[byte]](data)
    hmac(
      HashType, keyarr.toOpenArray(0, int(klen) - 1),
      dataarr.toOpenArray(0, int(ulen) - 1), implementation, cpufeatures)

  func hmac*(
      HashType: typedesc[DigestType],
      key: ptr byte,
      klen: uint,
      data: ptr byte,
      ulen: uint,
      implementation: Sha2Implementation,
  ): MDigest[HashType.bits] =
    var
      keyarr = cast[ptr UncheckedArray[byte]](key)
      dataarr = cast[ptr UncheckedArray[byte]](data)
    hmac(
      HashType, keyarr.toOpenArray(0, int(klen) - 1),
      dataarr.toOpenArray(0, int(ulen) - 1), implementation, defaultCpuFeatures)

  func hmac*(
      HashType: typedesc[DigestType],
      key: ptr byte,
      klen: uint,
      data: ptr byte,
      ulen: uint
  ): MDigest[HashType.bits] =
    var
      keyarr = cast[ptr UncheckedArray[byte]](key)
      dataarr = cast[ptr UncheckedArray[byte]](data)
    hmac(
      HashType, keyarr.toOpenArray(0, int(klen) - 1),
      dataarr.toOpenArray(0, int(ulen) - 1), Sha2Implementation.Auto,
      defaultCpuFeatures)

declareHmac(sha224)
declareHmac(sha256)
declareHmac(sha384)
declareHmac(sha512)
declareHmac(sha512_224)
declareHmac(sha512_256)
