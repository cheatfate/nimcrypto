#
#
#                    NimCrypto
#        (c) Copyright 2016 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module provides helper procedures for calculating secure digests
## supported by `nimcrypto` library.
import utils

{.deadCodeElim:on.}

const
  MaxMDigestLength* = 64
    ## Maximum size of generated digests by `nimcrypto` library is 64 octets.
  NimcryptoHexLowercase* = defined(nimcryptoLowercase)
    ## Compile your project with ``-d:nimcryptoLowercase`` to set all
    ## hexadecimal output in lowercase digits.
  Nimcrypto0xPrefix* = defined(nimcrypto0xPrefix)
    ## Compile your project with ``-d:nimcrypto0xPrefix`` to set all
    ## hexadecimal output to be prefixed with ``0x``.

type
  MDigest*[bits: static[int]] = object
    ## Message digest type
    data*: array[bits div 8, byte]

  bchar* = byte | char

proc `$`*(digest: MDigest): string =
  ## Return hexadecimal string representation of ``digest``.
  ##
  ##  .. code-block::nim
  ##    import nimcrypto
  ##
  ##    var digestHexString = $sha256.digest("Hello World!")
  ##    echo digestHexString
  when Nimcrypto0xPrefix:
    result = newString(len(digest.data) * 2 + 2)
    result[0] = '0'
    result[1] = 'x'
    let offset = 2
  else:
    result = newString(len(digest.data) * 2)
    let offset = 0

  when NimcryptoHexLowercase:
    let alpha = ord('a')
  else:
    let alpha = ord('A')

  for i in 0..<len(digest.data):
    let c = digest.data[i]
    let t1 = ord(c) shr 4
    let t0 = ord(c) and 0x0F
    let i0 = offset + i * 2
    let i1 = offset + i * 2 + 1
    case t1
      of 0..9: result[i0] = chr(t1 + ord('0'))
      else: result[i0] = chr(t1 - 10 + alpha)
    case t0:
      of 0..9: result[i1] = chr(t0 + ord('0'))
      else: result[i1] = chr(t0 - 10 + alpha)

proc digest*(HashType: typedesc, data: ptr byte,
             ulen: uint): MDigest[HashType.bits] =
  ## Calculate and return digest using algorithm ``HashType`` of data ``data``
  ## with length ``ulen``.
  ##
  ##  .. code-block::nim
  ##    import nimcrypto
  ##
  ##    var stringToHash = "Hello World!"
  ##    let data = cast[ptr byte](addr stringToHash[0])
  ##    let datalen = uint(len(stringToHash))
  ##    echo sha256.digest(data, datalen)
  mixin init, update, finish, clear
  var ctx: HashType
  ctx.init()
  ctx.update(data, ulen)
  result = ctx.finish()
  ctx.clear()

proc digest*[T](HashType: typedesc, data: openarray[T],
                ostart: int = 0, ofinish: int = -1): MDigest[HashType.bits] =
  ## Calculate and return digest using algorithm ``HashType`` of data ``data``
  ## in slice ``[ostart, ofinish]``, both ``ostart`` and ``ofinish`` are
  ## inclusive.
  ##
  ##  .. code-block::nim
  ##    import nimcrypto
  ##
  ##    var stringToHash = "Hello World!"
  ##    ## Calculate digest of whole string `Hello World!`.
  ##    echo sha256.digest(stringToHash)
  ##    ## Calcualte digest of `Hello`.
  ##    echo sha256.digest(stringToHash, ofinish = 4)
  ##    ## Calculate digest of `World!`.
  ##    echo sha256.digest(stringToHash, ostart = 6)
  ##    ## Calculate digest of constant `Hello`.
  ##    echo sha256.digest("Hello")
  ##    ## Calculate digest of constant `World!`.
  ##    echo sha256.digest("World!")
  mixin init, update, finish, clear
  var ctx: HashType
  let so = if ostart < 0: (len(data) + ostart) else: ostart
  let eo = if ofinish < 0: (len(data) + ofinish) else: ofinish
  let length = (eo - so + 1) * sizeof(T)
  ctx.init()
  if length <= 0:
    result = ctx.finish()
  else:
    ctx.update(cast[ptr byte](unsafeAddr data[so]), uint(length))
    result = ctx.finish()
  ctx.clear()

proc fromHex*(T: typedesc[MDigest], s: string): T =
  ## Create ``MDigest`` object from hexadecimal string representation.
  ##
  ##  .. code-block::nim
  ##    import nimcrypto
  ##
  ##    var a = MDigest[256].fromHex("7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9069")
  ##    echo $a
  ##    ## Get number of bits used by ``a``.
  ##    echo a.bits
  hexToBytes(s, result.data)

proc `==`*[A, B](d1: MDigest[A], d2: MDigest[B]): bool =
  ## Check for equality between two ``MDigest`` objects ``d1`` and ``d2``.
  ## If size in bits of ``d1`` is not equal to size in bits of ``d2`` then
  ## digests considered as not equal.
  if d1.bits != d2.bits:
    return false
  var n = len(d1.data)
  var res, diff: int
  while n > 0:
    dec(n)
    diff = int(d1.data[n]) - int(d2.data[n])
    res = (res and -not(diff)) or diff
  result = (res == 0)

when true:
  proc toDigestAux(n: static int, s: static string): MDigest[n] =
    static:
      assert n > 0 and n mod 8 == 0,
            "The provided hex string should have an even non-zero length"
    hexToBytes(s, result.data)

  template toDigest*(s: static string): auto =
    ## Convert hexadecimal string representation to ``MDigest`` object.
    ## This template can be used to create ``MDigest`` constants.
    ##
    ##  .. code-block::nim
    ##    import nimcrypto
    ##
    ##    const SomeDigest = "7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9069".toDigest
    ##    echo $SomeDigest
    ##    ## Get number of bits used by ``SomeDigest``.
    ##    echo SomeDigest.bits
    const digest = toDigestAux(len(s) * 4, s)
    digest

else:
  # This definition is shorter, but it turns out that it
  # triggers a Nim bug. Calls to `toDigest` will compile,
  # but the result values won't be considered the same
  # type as MDigest[N] even when s.len * 4 == N
  proc toDigest*(s: static string): MDigest[s.len * 4] =
    static:
      assert s.len > 0 and s.len mod 2 == 0,
            "The provided hex string should have an even non-zero length"
    const digest = hexToBytes(s, result.data)
    return digest
