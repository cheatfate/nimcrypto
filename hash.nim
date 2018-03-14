import utils

const
  MaxMdDigestLength* = 64

type
  MdDigest* = object
    size*: uint
    data*: array[MaxMdDigestLength, uint8]

proc `$`*(digest: MdDigest): string =
  result = ""
  var i = 0'u
  while i < digest.size:
    result &= hexChar(cast[uint8](digest.data[i]))
    inc(i)
