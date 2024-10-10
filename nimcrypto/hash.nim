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
import ./utils

const
  MaxMDigestLength* = 64
    ## Maximum size of generated digests by `nimcrypto` library is 64 octets.
  NimcryptoHexLowercase* = defined(nimcryptoLowercase)
    ## Compile your project with ``-d:nimcryptoLowercase`` to set all
    ## hexadecimal output in lowercase digits.
  Nimcrypto0xPrefix* = defined(nimcrypto0xPrefix)
    ## Compile your project with ``-d:nimcrypto0xPrefix`` to set all
    ## hexadecimal output to be prefixed with ``0x``.

  MDigestAlignment* = when defined(nimMemAlignTiny): 4
    elif sizeof(int) == 8: 16
    else: 8
    ## Aligning the digest to a reasonable boundary allows for more efficient
    ## copying and zero:ing - however, we cannot over-align the type with
    ## respect to the dynamic memory allocator or heap-based instances might
    ## end up causing unaligned reads with aligned instructions.
    ##
    ## See also:
    ## https://github.com/nim-lang/Nim/blob/v1.6.14/lib/system/bitmasks.nim#L22
    ## https://en.cppreference.com/w/cpp/types/max_align_t
    # TODO https://github.com/nim-lang/Nim/issues/22482 (on 32-bit refc, `new`
    #      incorrectly aligns to 8)
    #      https://github.com/cheatfate/nimcrypto/issues/69 1.6.12 has debilitating bugs

  MDigestAligned* = (NimMajor, NimMinor, NimPatch) >= (1, 6, 14)

when MDigestAligned:
  type
    MDigest*[bits: static[int]] = object
      ## Message digest type
      # We want the largest alignment such that:
      # * the alignment evenly divides the size of the type (to avoid padding)
      # * the alignment is not greater than the type (to avoid padding)
      # * the alignment isn't greater than what `new` guaranteees
      # TODO https://github.com/nim-lang/Nim/issues/22474 any kind of template
      # evaluation in when.. including >=! *sigh*
      when ((bits div 8) mod 16 == 0 and not ((bits div 8) < 16) and
          not (MDigestAlignment < 16)):
        data* {.align: 16.}: array[bits div 8, byte]
      elif ((bits div 8) mod 8 == 0 and not ((bits div 8) < 8) and
          not (MDigestAlignment < 8)):
        data* {.align: 8.}: array[bits div 8, byte]
      elif ((bits div 8) mod 4 == 0 and not ((bits div 8) < 4) and
          not (MDigestAlignment < 4)):
        data* {.align: 4.}: array[bits div 8, byte]
      else:
        data*: array[bits div 8, byte]

else:
  type
    MDigest*[bits: static[int]] = object
      ## Message digest type
      data*: array[bits div 8, byte]

proc `$`*(digest: MDigest): string =
  ## Return hexadecimal string representation of ``digest``.
  ##
  ##  .. code-block::nim
  ##    import nimcrypto
  ##
  ##    var digestHexString = $sha256.digest("Hello World!")
  ##    echo digestHexString
  var res = newString((len(digest.data) shl 1))
  when NimcryptoHexLowercase:
    discard bytesToHex(digest.data, res, {HexFlags.LowerCase})
  else:
    discard bytesToHex(digest.data, res, {})
  when Nimcrypto0xPrefix:
    "0x" & res
  else:
    res

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

proc digest*[T: bchar](HashType: typedesc,
                       data: openArray[T]): MDigest[HashType.bits] =
  ## Calculate and return digest using algorithm ``HashType`` of data ``data``
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
  ctx.init()
  ctx.update(data)
  result = ctx.finish()
  ctx.clear()

proc digest*[T](HashType: typedesc, data: openArray[T],
                ostart: int, ofinish = -1): MDigest[HashType.bits] {.
     deprecated: "Use digest(data.toOpenArray()) instead", inline.} =
  if ofinish < 0:
    result = digest(HashType, data.toOpenArray(ostart, len(data) - 1))
  else:
    result = digest(HashType, data.toOpenArray(ostart, ofinish))

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
  when d1.bits == d2.bits:
    equalMemFull(d1.data, d2.data)
  else:
    false

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
