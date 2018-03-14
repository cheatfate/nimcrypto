import utils

type
  MDigest*[bits: static[int]] = object
    data*: array[bits div 8, uint8]

proc `$`*(digest: MDigest): string =
  result = ""
  var i = 0'u
  while i < len(digest.data):
    result &= hexChar(cast[uint8](digest.data[i]))
    inc(i)
