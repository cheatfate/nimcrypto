#
#
#                    NimCrypto
#        (c) Copyright 2016 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

import utils

{.deadCodeElim:on.}

const
  MaxMDigestLength* = 64

type
  MDigest*[bits: static[int]] = object
    data*: array[bits div 8, byte]

  bchar* = byte | char

proc `$`*(digest: MDigest): string =
  result = ""
  var i = 0'u
  while i < uint(len(digest.data)):
    result &= hexChar(cast[byte](digest.data[i]))
    inc(i)

proc digest*(HashType: typedesc, data: ptr byte,
             ulen: uint): MDigest[HashType.bits] =
  mixin init, update, finish, clear
  var ctx: HashType
  ctx.init()
  ctx.update(data, ulen)
  result = ctx.finish()
  ctx.clear()

proc digest*[T](HashType: typedesc, data: openarray[T],
                ostart: int = 0, ofinish: int = -1): MDigest[HashType.bits] =
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

proc fromHex*(T: type MDigest, s: string): T =
  hexToBytes(s, result.data)

proc toDigest*(s: static string): MDigest[s.len * 4] =
  hexToBytes(s, result.data)

