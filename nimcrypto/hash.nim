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
                ostart: int = -1, ofinish: int = -1): MDigest[HashType.bits] =
  mixin init, update, finish
  var ctx: HashType
  assert(ostart >= -1 and ofinish >= -1)
  let so = if ostart == -1: 0 else: ostart
  let eo = if ofinish == -1: uint(len(data)) else: uint(ofinish - so)
  ctx.init()
  assert(uint(so) <= eo)
  assert(eo <= uint(len(data)))
  if eo == 0:
    result = ctx.finish()
  else:
    ctx.update(cast[ptr uint8](unsafeAddr data[so]), uint(sizeof(T)) * eo)
    result = ctx.finish()
