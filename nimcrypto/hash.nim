import utils

const
  MaxMDigestLength* = 64

type
  MDigest*[bits: static[int]] = object
    data*: array[bits div 8, uint8]

proc `$`*(digest: MDigest): string =
  result = ""
  var i = 0'u
  while i < uint(len(digest.data)):
    result &= hexChar(cast[uint8](digest.data[i]))
    inc(i)

proc digest*(HashType: typedesc, data: ptr uint8,
             ulen: uint): MDigest[HashType.bits] =
  mixin init, update, finish
  var ctx: HashType
  ctx.init()
  ctx.update(data, ulen)
  result = ctx.finish()

proc digest*[T](HashType: typedesc, data: openarray[T],
                ostart: int = 0, ofinish: int = -1): MDigest[HashType.bits] =
  mixin init, update, finish
  var ctx: HashType
  let so = if ostart < 0: (len(data) + ostart) else: ostart
  let eo = if ofinish < 0: (len(data) + ofinish) else: ofinish
  let length = (eo - so + 1) * sizeof(T)
  ctx.init()
  if length <= 0:
    result = ctx.finish()
  else:
    ctx.update(cast[ptr uint8](unsafeAddr data[so]), uint(length))
    result = ctx.finish()
