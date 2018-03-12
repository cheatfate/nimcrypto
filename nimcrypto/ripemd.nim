#
#
#                    NimCrypto
#        (c) Copyright 2016-2018 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements RIPEMD set of cryptographic hash functions,
## designed by Hans Dobbertin, Antoon Bosselaers and Bart Preneel.
## [http://www.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf]
##
## This module is Nim adoptation of original C source code by
## Antoon Bosselaers.
## [https://homes.esat.kuleuven.be/~bosselae/ripemd160/ps/AB-9601/rmd160.c]
##
## This module includes support of RIPEMD-128/160/256/320.
## 
## Tests made according to official test vectors
## [https://homes.esat.kuleuven.be/~bosselae/ripemd160.html].

import hash, utils

type
  ripemd128* = ref object of MdContext
    count: array[2, uint32]
    state: array[4, uint32]
    buffer: array[64, uint8]

  ripemd160* = ref object of MdContext
    count: array[2, uint32]
    state: array[5, uint32]
    buffer: array[64, uint8]

  ripemd256* = ref object of MdContext
    count: array[2, uint32]
    state: array[8, uint32]
    buffer: array[64, uint8]

  ripemd320* = ref object of MdContext
    count: array[2, uint32]
    state: array[10, uint32]
    buffer: array[64, uint8]
    
  ripemd* = ripemd128 | ripemd160 | ripemd256 | ripemd320

# Five basic functions F(), G() and H()
template F(x, y, z: untyped): untyped =
  # x^y^z
  ((x) xor (y) xor (z))

template G(x, y, z: untyped): untyped =
  # (x&y)|(~x&z)
  (((x) and (y)) or (not (x) and (z)))

template H(x, y, z: untyped): untyped =
  # (x|~y)^z
  (((x) or not (y)) xor (z))

template I(x, y, z: untyped): untyped =
  # (x&z)|(y&~z)
  (((x) and (z)) or ((y) and not (z)))

template J(x, y, z: untyped): untyped =
  # x^(y|~z)
  ((x) xor ((y) or not (z)))

# Eight basic operations FF() through III() for 128 and 256 bits
template FF128(a, b, c, d, x, s: untyped): void =
  (a) = (a) + F((b), (c), (d)) + (x)
  (a) = ROL(uint32(a), (s))

template GG128(a, b, c, d, x, s: untyped): void =
  (a) = (a) + G((b), (c), (d)) + (x) + 0x5A827999'u32
  (a) = ROL(uint32(a), (s))

template HH128(a, b, c, d, x, s: untyped): void =
  (a) = (a) + H((b), (c), (d)) + (x) + 0x6ED9EBA1'u32
  (a) = ROL(uint32(a), (s))

template II128(a, b, c, d, x, s: untyped): void =
  (a) = (a) + I((b), (c), (d)) + (x) + 0x8F1BBCDC'u32
  (a) = ROL(uint32(a), (s))

template FFF128(a, b, c, d, x, s: untyped): void =
  (a) = (a) + F((b), (c), (d)) + (x)
  (a) = ROL(uint32(a), (s))

template GGG128(a, b, c, d, x, s: untyped): void =
  (a) = (a) + G((b), (c), (d)) + (x) + 0x6D703EF3'u32
  (a) = ROL(uint32(a), (s))

template HHH128(a, b, c, d, x, s: untyped): void =
  (a) = (a) + H((b), (c), (d)) + (x) + 0x5C4DD124'u32
  (a) = ROL(uint32(a), (s))

template III128(a, b, c, d, x, s: untyped): void =
  (a) = (a) + I((b), (c), (d)) + (x) + 0x50A28BE6'u32
  (a) = ROL((a), (s))

# Ten basic operations FF() through III() for 160 and 320 bits
template FF160(a, b, c, d, e, x, s: untyped): void =
  (a) = (a) + F((b), (c), (d)) + (x)
  (a) = ROL(uint32(a), (s)) + (e)
  (c) = ROL(uint32(c), 10)

template GG160(a, b, c, d, e, x, s: untyped): void =
  (a) = (a) + G((b), (c), (d)) + (x) + 0x5A827999'u32
  (a) = ROL(uint32(a), (s)) + (e)
  (c) = ROL(uint32(c), 10)

template HH160(a, b, c, d, e, x, s: untyped): void =
  (a) = (a) +  H((b), (c), (d)) + (x) + 0x6ED9EBA1'u32
  (a) = ROL(uint32(a), (s)) + (e)
  (c) = ROL(uint32(c), 10)

template II160(a, b, c, d, e, x, s: untyped): void =
  (a) = (a) + I((b), (c), (d)) + (x) + 0x8F1BBCDC'u32
  (a) = ROL(uint32(a), (s)) + (e)
  (c) = ROL(uint32(c), 10)

template JJ160(a, b, c, d, e, x, s: untyped): void =
  (a) = (a) + J((b), (c), (d)) + (x) + 0xA953FD4E'u32
  (a) = ROL(uint32(a), (s)) + (e)
  (c) = ROL(uint32(c), 10)

template FFF160(a, b, c, d, e, x, s: untyped): void =
  (a) = (a) + F((b), (c), (d)) + (x)
  (a) = ROL(uint32(a), (s)) + (e)
  (c) = ROL(uint32(c), 10)

template GGG160(a, b, c, d, e, x, s: untyped): void =
  (a) = (a) + G((b), (c), (d)) + (x) + 0x7A6D76E9'u32
  (a) = ROL(uint32(a), (s)) + (e)
  (c) = ROL(uint32(c), 10)

template HHH160(a, b, c, d, e, x, s: untyped): void =
  (a) = (a) + H((b), (c), (d)) + (x) + 0x6D703EF3'u32
  (a) = ROL(uint32(a), (s)) + (e)
  (c) = ROL(uint32(c), 10)

template III160(a, b, c, d, e, x, s: untyped): void =
  (a) = (a) + I((b), (c), (d)) + (x) + 0x5C4DD124'u32
  (a) = ROL(uint32(a), (s)) + (e)
  (c) = ROL(uint32(c), 10)

template JJJ160(a, b, c, d, e, x, s: untyped): void =
  (a) = (a) + J((b), (c), (d)) + (x) + 0x50A28BE6'u32
  (a) = ROL(uint32(a), (s)) + (e)
  (c) = ROL(uint32(c), 10)

template LROUND128N1(a, b, c, d, x): void =
  FF128(a, b, c, d, x[ 0], 11)
  FF128(d, a, b, c, x[ 1], 14)
  FF128(c, d, a, b, x[ 2], 15)
  FF128(b, c, d, a, x[ 3], 12)
  FF128(a, b, c, d, x[ 4],  5)
  FF128(d, a, b, c, x[ 5],  8)
  FF128(c, d, a, b, x[ 6],  7)
  FF128(b, c, d, a, x[ 7],  9)
  FF128(a, b, c, d, x[ 8], 11)
  FF128(d, a, b, c, x[ 9], 13)
  FF128(c, d, a, b, x[10], 14)
  FF128(b, c, d, a, x[11], 15)
  FF128(a, b, c, d, x[12],  6)
  FF128(d, a, b, c, x[13],  7)
  FF128(c, d, a, b, x[14],  9)
  FF128(b, c, d, a, x[15],  8)

template LROUND128N2(a, b, c, d, x): void =
  GG128(a, b, c, d, x[ 7],  7)
  GG128(d, a, b, c, x[ 4],  6)
  GG128(c, d, a, b, x[13],  8)
  GG128(b, c, d, a, x[ 1], 13)
  GG128(a, b, c, d, x[10], 11)
  GG128(d, a, b, c, x[ 6],  9)
  GG128(c, d, a, b, x[15],  7)
  GG128(b, c, d, a, x[ 3], 15)
  GG128(a, b, c, d, x[12],  7)
  GG128(d, a, b, c, x[ 0], 12)
  GG128(c, d, a, b, x[ 9], 15)
  GG128(b, c, d, a, x[ 5],  9)
  GG128(a, b, c, d, x[ 2], 11)
  GG128(d, a, b, c, x[14],  7)
  GG128(c, d, a, b, x[11], 13)
  GG128(b, c, d, a, x[ 8], 12)

template LROUND128N3(a, b, c, d, x): void =
  HH128(a, b, c, d, x[ 3], 11)
  HH128(d, a, b, c, x[10], 13)
  HH128(c, d, a, b, x[14],  6)
  HH128(b, c, d, a, x[ 4],  7)
  HH128(a, b, c, d, x[ 9], 14)
  HH128(d, a, b, c, x[15],  9)
  HH128(c, d, a, b, x[ 8], 13)
  HH128(b, c, d, a, x[ 1], 15)
  HH128(a, b, c, d, x[ 2], 14)
  HH128(d, a, b, c, x[ 7],  8)
  HH128(c, d, a, b, x[ 0], 13)
  HH128(b, c, d, a, x[ 6],  6)
  HH128(a, b, c, d, x[13],  5)
  HH128(d, a, b, c, x[11], 12)
  HH128(c, d, a, b, x[ 5],  7)
  HH128(b, c, d, a, x[12],  5)

template LROUND128N4(a, b, c, d, x): void =
  II128(a, b, c, d, x[ 1], 11)
  II128(d, a, b, c, x[ 9], 12)
  II128(c, d, a, b, x[11], 14)
  II128(b, c, d, a, x[10], 15)
  II128(a, b, c, d, x[ 0], 14)
  II128(d, a, b, c, x[ 8], 15)
  II128(c, d, a, b, x[12],  9)
  II128(b, c, d, a, x[ 4],  8)
  II128(a, b, c, d, x[13],  9)
  II128(d, a, b, c, x[ 3], 14)
  II128(c, d, a, b, x[ 7],  5)
  II128(b, c, d, a, x[15],  6)
  II128(a, b, c, d, x[14],  8)
  II128(d, a, b, c, x[ 5],  6)
  II128(c, d, a, b, x[ 6],  5)
  II128(b, c, d, a, x[ 2], 12)

template RROUND128N1(a, b, c, d, x): void =
  III128(a, b, c, d, x[ 5],  8)
  III128(d, a, b, c, x[14],  9)
  III128(c, d, a, b, x[ 7],  9)
  III128(b, c, d, a, x[ 0], 11)
  III128(a, b, c, d, x[ 9], 13)
  III128(d, a, b, c, x[ 2], 15)
  III128(c, d, a, b, x[11], 15)
  III128(b, c, d, a, x[ 4],  5)
  III128(a, b, c, d, x[13],  7)
  III128(d, a, b, c, x[ 6],  7)
  III128(c, d, a, b, x[15],  8)
  III128(b, c, d, a, x[ 8], 11)
  III128(a, b, c, d, x[ 1], 14)
  III128(d, a, b, c, x[10], 14)
  III128(c, d, a, b, x[ 3], 12)
  III128(b, c, d, a, x[12],  6)

template RROUND128N2(a, b, c, d, x): void =
  HHH128(a, b, c, d, x[ 6],  9)
  HHH128(d, a, b, c, x[11], 13)
  HHH128(c, d, a, b, x[ 3], 15)
  HHH128(b, c, d, a, x[ 7],  7)
  HHH128(a, b, c, d, x[ 0], 12)
  HHH128(d, a, b, c, x[13],  8)
  HHH128(c, d, a, b, x[ 5],  9)
  HHH128(b, c, d, a, x[10], 11)
  HHH128(a, b, c, d, x[14],  7)
  HHH128(d, a, b, c, x[15],  7)
  HHH128(c, d, a, b, x[ 8], 12)
  HHH128(b, c, d, a, x[12],  7)
  HHH128(a, b, c, d, x[ 4],  6)
  HHH128(d, a, b, c, x[ 9], 15)
  HHH128(c, d, a, b, x[ 1], 13)
  HHH128(b, c, d, a, x[ 2], 11)

template RROUND128N3(a, b, c, d, x): void =
  GGG128(a, b, c, d, x[15],  9)
  GGG128(d, a, b, c, x[ 5],  7)
  GGG128(c, d, a, b, x[ 1], 15)
  GGG128(b, c, d, a, x[ 3], 11)
  GGG128(a, b, c, d, x[ 7],  8)
  GGG128(d, a, b, c, x[14],  6)
  GGG128(c, d, a, b, x[ 6],  6)
  GGG128(b, c, d, a, x[ 9], 14)
  GGG128(a, b, c, d, x[11], 12)
  GGG128(d, a, b, c, x[ 8], 13)
  GGG128(c, d, a, b, x[12],  5)
  GGG128(b, c, d, a, x[ 2], 14)
  GGG128(a, b, c, d, x[10], 13)
  GGG128(d, a, b, c, x[ 0], 13)
  GGG128(c, d, a, b, x[ 4],  7)
  GGG128(b, c, d, a, x[13],  5)

template RROUND128N4(a, b, c, d, x): void =
  FFF128(a, b, c, d, x[ 8], 15)
  FFF128(d, a, b, c, x[ 6],  5)
  FFF128(c, d, a, b, x[ 4],  8)
  FFF128(b, c, d, a, x[ 1], 11)
  FFF128(a, b, c, d, x[ 3], 14)
  FFF128(d, a, b, c, x[11], 14)
  FFF128(c, d, a, b, x[15],  6)
  FFF128(b, c, d, a, x[ 0], 14)
  FFF128(a, b, c, d, x[ 5],  6)
  FFF128(d, a, b, c, x[12],  9)
  FFF128(c, d, a, b, x[ 2], 12)
  FFF128(b, c, d, a, x[13],  9)
  FFF128(a, b, c, d, x[ 9], 12)
  FFF128(d, a, b, c, x[ 7],  5)
  FFF128(c, d, a, b, x[10], 15)
  FFF128(b, c, d, a, x[14],  8)

template LROUND160N1(a, b, c, d, e, x): void =
  FF160(a, b, c, d, e, x[ 0], 11)
  FF160(e, a, b, c, d, x[ 1], 14)
  FF160(d, e, a, b, c, x[ 2], 15)
  FF160(c, d, e, a, b, x[ 3], 12)
  FF160(b, c, d, e, a, x[ 4],  5)
  FF160(a, b, c, d, e, x[ 5],  8)
  FF160(e, a, b, c, d, x[ 6],  7)
  FF160(d, e, a, b, c, x[ 7],  9)
  FF160(c, d, e, a, b, x[ 8], 11)
  FF160(b, c, d, e, a, x[ 9], 13)
  FF160(a, b, c, d, e, x[10], 14)
  FF160(e, a, b, c, d, x[11], 15)
  FF160(d, e, a, b, c, x[12],  6)
  FF160(c, d, e, a, b, x[13],  7)
  FF160(b, c, d, e, a, x[14],  9)
  FF160(a, b, c, d, e, x[15],  8)

template LROUND160N2(a, b, c, d, e, x): void =
  GG160(e, a, b, c, d, x[ 7],  7)
  GG160(d, e, a, b, c, x[ 4],  6)
  GG160(c, d, e, a, b, x[13],  8)
  GG160(b, c, d, e, a, x[ 1], 13)
  GG160(a, b, c, d, e, x[10], 11)
  GG160(e, a, b, c, d, x[ 6],  9)
  GG160(d, e, a, b, c, x[15],  7)
  GG160(c, d, e, a, b, x[ 3], 15)
  GG160(b, c, d, e, a, x[12],  7)
  GG160(a, b, c, d, e, x[ 0], 12)
  GG160(e, a, b, c, d, x[ 9], 15)
  GG160(d, e, a, b, c, x[ 5],  9)
  GG160(c, d, e, a, b, x[ 2], 11)
  GG160(b, c, d, e, a, x[14],  7)
  GG160(a, b, c, d, e, x[11], 13)
  GG160(e, a, b, c, d, x[ 8], 12)

template LROUND160N3(a, b, c, d, e, x): void =
  HH160(d, e, a, b, c, x[ 3], 11)
  HH160(c, d, e, a, b, x[10], 13)
  HH160(b, c, d, e, a, x[14],  6)
  HH160(a, b, c, d, e, x[ 4],  7)
  HH160(e, a, b, c, d, x[ 9], 14)
  HH160(d, e, a, b, c, x[15],  9)
  HH160(c, d, e, a, b, x[ 8], 13)
  HH160(b, c, d, e, a, x[ 1], 15)
  HH160(a, b, c, d, e, x[ 2], 14)
  HH160(e, a, b, c, d, x[ 7],  8)
  HH160(d, e, a, b, c, x[ 0], 13)
  HH160(c, d, e, a, b, x[ 6],  6)
  HH160(b, c, d, e, a, x[13],  5)
  HH160(a, b, c, d, e, x[11], 12)
  HH160(e, a, b, c, d, x[ 5],  7)
  HH160(d, e, a, b, c, x[12],  5)

template LROUND160N4(a, b, c, d, e, x): void =
  II160(c, d, e, a, b, x[ 1], 11)
  II160(b, c, d, e, a, x[ 9], 12)
  II160(a, b, c, d, e, x[11], 14)
  II160(e, a, b, c, d, x[10], 15)
  II160(d, e, a, b, c, x[ 0], 14)
  II160(c, d, e, a, b, x[ 8], 15)
  II160(b, c, d, e, a, x[12],  9)
  II160(a, b, c, d, e, x[ 4],  8)
  II160(e, a, b, c, d, x[13],  9)
  II160(d, e, a, b, c, x[ 3], 14)
  II160(c, d, e, a, b, x[ 7],  5)
  II160(b, c, d, e, a, x[15],  6)
  II160(a, b, c, d, e, x[14],  8)
  II160(e, a, b, c, d, x[ 5],  6)
  II160(d, e, a, b, c, x[ 6],  5)
  II160(c, d, e, a, b, x[ 2], 12)

template LROUND160N5(a, b, c, d, e, x): void =
  JJ160(b, c, d, e, a, x[ 4],  9)
  JJ160(a, b, c, d, e, x[ 0], 15)
  JJ160(e, a, b, c, d, x[ 5],  5)
  JJ160(d, e, a, b, c, x[ 9], 11)
  JJ160(c, d, e, a, b, x[ 7],  6)
  JJ160(b, c, d, e, a, x[12],  8)
  JJ160(a, b, c, d, e, x[ 2], 13)
  JJ160(e, a, b, c, d, x[10], 12)
  JJ160(d, e, a, b, c, x[14],  5)
  JJ160(c, d, e, a, b, x[ 1], 12)
  JJ160(b, c, d, e, a, x[ 3], 13)
  JJ160(a, b, c, d, e, x[ 8], 14)
  JJ160(e, a, b, c, d, x[11], 11)
  JJ160(d, e, a, b, c, x[ 6],  8)
  JJ160(c, d, e, a, b, x[15],  5)
  JJ160(b, c, d, e, a, x[13],  6)

template RROUND160N1(a, b, c, d, e, x): void =
  JJJ160(a, b, c, d, e, x[ 5],  8)
  JJJ160(e, a, b, c, d, x[14],  9)
  JJJ160(d, e, a, b, c, x[ 7],  9)
  JJJ160(c, d, e, a, b, x[ 0], 11)
  JJJ160(b, c, d, e, a, x[ 9], 13)
  JJJ160(a, b, c, d, e, x[ 2], 15)
  JJJ160(e, a, b, c, d, x[11], 15)
  JJJ160(d, e, a, b, c, x[ 4],  5)
  JJJ160(c, d, e, a, b, x[13],  7)
  JJJ160(b, c, d, e, a, x[ 6],  7)
  JJJ160(a, b, c, d, e, x[15],  8)
  JJJ160(e, a, b, c, d, x[ 8], 11)
  JJJ160(d, e, a, b, c, x[ 1], 14)
  JJJ160(c, d, e, a, b, x[10], 14)
  JJJ160(b, c, d, e, a, x[ 3], 12)
  JJJ160(a, b, c, d, e, x[12],  6)

template RROUND160N2(a, b, c, d, e, x): void =
  III160(e, a, b, c, d, x[ 6],  9)
  III160(d, e, a, b, c, x[11], 13)
  III160(c, d, e, a, b, x[ 3], 15)
  III160(b, c, d, e, a, x[ 7],  7)
  III160(a, b, c, d, e, x[ 0], 12)
  III160(e, a, b, c, d, x[13],  8)
  III160(d, e, a, b, c, x[ 5],  9)
  III160(c, d, e, a, b, x[10], 11)
  III160(b, c, d, e, a, x[14],  7)
  III160(a, b, c, d, e, x[15],  7)
  III160(e, a, b, c, d, x[ 8], 12)
  III160(d, e, a, b, c, x[12],  7)
  III160(c, d, e, a, b, x[ 4],  6)
  III160(b, c, d, e, a, x[ 9], 15)
  III160(a, b, c, d, e, x[ 1], 13)
  III160(e, a, b, c, d, x[ 2], 11)

template RROUND160N3(a, b, c, d, e, x): void =
  HHH160(d, e, a, b, c, x[15],  9)
  HHH160(c, d, e, a, b, x[ 5],  7)
  HHH160(b, c, d, e, a, x[ 1], 15)
  HHH160(a, b, c, d, e, x[ 3], 11)
  HHH160(e, a, b, c, d, x[ 7],  8)
  HHH160(d, e, a, b, c, x[14],  6)
  HHH160(c, d, e, a, b, x[ 6],  6)
  HHH160(b, c, d, e, a, x[ 9], 14)
  HHH160(a, b, c, d, e, x[11], 12)
  HHH160(e, a, b, c, d, x[ 8], 13)
  HHH160(d, e, a, b, c, x[12],  5)
  HHH160(c, d, e, a, b, x[ 2], 14)
  HHH160(b, c, d, e, a, x[10], 13)
  HHH160(a, b, c, d, e, x[ 0], 13)
  HHH160(e, a, b, c, d, x[ 4],  7)
  HHH160(d, e, a, b, c, x[13],  5)

template RROUND160N4(a, b, c, d, e, x): void =
  GGG160(c, d, e, a, b, x[ 8], 15)
  GGG160(b, c, d, e, a, x[ 6],  5)
  GGG160(a, b, c, d, e, x[ 4],  8)
  GGG160(e, a, b, c, d, x[ 1], 11)
  GGG160(d, e, a, b, c, x[ 3], 14)
  GGG160(c, d, e, a, b, x[11], 14)
  GGG160(b, c, d, e, a, x[15],  6)
  GGG160(a, b, c, d, e, x[ 0], 14)
  GGG160(e, a, b, c, d, x[ 5],  6)
  GGG160(d, e, a, b, c, x[12],  9)
  GGG160(c, d, e, a, b, x[ 2], 12)
  GGG160(b, c, d, e, a, x[13],  9)
  GGG160(a, b, c, d, e, x[ 9], 12)
  GGG160(e, a, b, c, d, x[ 7],  5)
  GGG160(d, e, a, b, c, x[10], 15)
  GGG160(c, d, e, a, b, x[14],  8)

template RROUND160N5(a, b, c, d, e, x): void =
  FFF160(b, c, d, e, a, x[12] ,  8)
  FFF160(a, b, c, d, e, x[15] ,  5)
  FFF160(e, a, b, c, d, x[10] , 12)
  FFF160(d, e, a, b, c, x[ 4] ,  9)
  FFF160(c, d, e, a, b, x[ 1] , 12)
  FFF160(b, c, d, e, a, x[ 5] ,  5)
  FFF160(a, b, c, d, e, x[ 8] , 14)
  FFF160(e, a, b, c, d, x[ 7] ,  6)
  FFF160(d, e, a, b, c, x[ 6] ,  8)
  FFF160(c, d, e, a, b, x[ 2] , 13)
  FFF160(b, c, d, e, a, x[13] ,  6)
  FFF160(a, b, c, d, e, x[14] ,  5)
  FFF160(e, a, b, c, d, x[ 0] , 15)
  FFF160(d, e, a, b, c, x[ 3] , 13)
  FFF160(c, d, e, a, b, x[ 9] , 11)
  FFF160(b, c, d, e, a, x[11] , 11)

proc ripemd128Transform(state: var array[4, uint32], data: ptr uint8) =
  var
    aa = state[0]
    bb = state[1]
    cc = state[2]
    dd = state[3]
    aaa = state[0]
    bbb = state[1]
    ccc = state[2]
    ddd = state[3]
    X = cast[ptr UncheckedArray[uint32]](data)

  LROUND128N1(aa, bb, cc, dd, X)
  LROUND128N2(aa, bb, cc, dd, X)
  LROUND128N3(aa, bb, cc, dd, X)
  LROUND128N4(aa, bb, cc, dd, X)
  RROUND128N1(aaa, bbb, ccc, ddd, X)
  RROUND128N2(aaa, bbb, ccc, ddd, X)
  RROUND128N3(aaa, bbb, ccc, ddd, X)
  RROUND128N4(aaa, bbb, ccc, ddd, X)

  # combine results
  ddd = ddd + cc + state[1]
  state[1] = state[2] + dd + aaa
  state[2] = state[3] + aa + bbb
  state[3] = state[0] + bb + ccc
  state[0] = ddd

proc ripemd256Transform(state: var array[8, uint32], data: ptr uint8) =
  var
    aa = state[0]
    bb = state[1]
    cc = state[2]
    dd = state[3]
    aaa = state[4]
    bbb = state[5]
    ccc = state[6]
    ddd = state[7]
    X = cast[ptr UncheckedArray[uint32]](data)

  LROUND128N1(aa, bb, cc, dd, X)
  RROUND128N1(aaa, bbb, ccc, ddd, X)
  swap(aa, aaa)
  LROUND128N2(aa, bb, cc, dd, X)
  RROUND128N2(aaa, bbb, ccc, ddd, X)
  swap(bb, bbb)
  LROUND128N3(aa, bb, cc, dd, X)
  RROUND128N3(aaa, bbb, ccc, ddd, X)
  swap(cc, ccc)
  LROUND128N4(aa, bb, cc, dd, X)
  RROUND128N4(aaa, bbb, ccc, ddd, X)
  swap(dd, ddd)

  # combine results
  state[0] = state[0] + aa
  state[1] = state[1] + bb
  state[2] = state[2] + cc
  state[3] = state[3] + dd
  state[4] = state[4] + aaa
  state[5] = state[5] + bbb
  state[6] = state[6] + ccc
  state[7] = state[7] + ddd

proc ripemd160Transform(state: var array[5, uint32], data: ptr uint8) =
  var
    aa = state[0]
    bb = state[1]
    cc = state[2]
    dd = state[3]
    ee = state[4]
    aaa = state[0]
    bbb = state[1]
    ccc = state[2]
    ddd = state[3]
    eee = state[4]
    X = cast[ptr UncheckedArray[uint32]](data)

  LROUND160N1(aa, bb, cc, dd, ee, X)
  LROUND160N2(aa, bb, cc, dd, ee, X)
  LROUND160N3(aa, bb, cc, dd, ee, X)
  LROUND160N4(aa, bb, cc, dd, ee, X)
  LROUND160N5(aa, bb, cc, dd, ee, X)
  RROUND160N1(aaa, bbb, ccc, ddd, eee, X)
  RROUND160N2(aaa, bbb, ccc, ddd, eee, X)
  RROUND160N3(aaa, bbb, ccc, ddd, eee, X)
  RROUND160N4(aaa, bbb, ccc, ddd, eee, X)
  RROUND160N5(aaa, bbb, ccc, ddd, eee, X)

  # combine results
  ddd = ddd + cc + state[1]
  state[1] = state[2] + dd + eee
  state[2] = state[3] + ee + aaa
  state[3] = state[4] + aa + bbb
  state[4] = state[0] + bb + ccc
  state[0] = ddd

proc ripemd320Transform(state: var array[10, uint32], data: ptr uint8) =
  var
    aa = state[0]
    bb = state[1]
    cc = state[2]
    dd = state[3]
    ee = state[4]
    aaa = state[5]
    bbb = state[6]
    ccc = state[7]
    ddd = state[8]
    eee = state[9]
    X = cast[ptr UncheckedArray[uint32]](data)

  LROUND160N1(aa, bb, cc, dd, ee, X)
  RROUND160N1(aaa, bbb, ccc, ddd, eee, X)
  swap(aa, aaa)
  LROUND160N2(aa, bb, cc, dd, ee, X)
  RROUND160N2(aaa, bbb, ccc, ddd, eee, X)
  swap(bb, bbb)
  LROUND160N3(aa, bb, cc, dd, ee, X)
  RROUND160N3(aaa, bbb, ccc, ddd, eee, X)
  swap(cc, ccc)
  LROUND160N4(aa, bb, cc, dd, ee, X)
  RROUND160N4(aaa, bbb, ccc, ddd, eee, X)
  swap(dd, ddd)
  LROUND160N5(aa, bb, cc, dd, ee, X)
  RROUND160N5(aaa, bbb, ccc, ddd, eee, X)
  swap(ee, eee)

  # combine results
  state[0] = state[0] + aa
  state[1] = state[1] + bb
  state[2] = state[2] + cc
  state[3] = state[3] + dd
  state[4] = state[4] + ee
  state[5] = state[5] + aaa
  state[6] = state[6] + bbb
  state[7] = state[7] + ccc
  state[8] = state[8] + ddd
  state[9] = state[9] + eee

proc init*[T: ripemd](ctx: T) =
  ctx.count[0] = 0
  ctx.count[1] = 0

  for i in 0..15:
    ctx.buffer[i] = 0

  when T is ripemd128:
    ctx.state[0] = 0x67452301'u32
    ctx.state[1] = 0xEFCDAB89'u32
    ctx.state[2] = 0x98BADCFE'u32
    ctx.state[3] = 0x10325476'u32
    ctx.sizeBlock = 64
    ctx.sizeDigest = 16
  elif T is ripemd160:
    ctx.state[0] = 0x67452301'u32
    ctx.state[1] = 0xEFCDAB89'u32
    ctx.state[2] = 0x98BADCFE'u32
    ctx.state[3] = 0x10325476'u32
    ctx.state[4] = 0xC3D2E1F0'u32
    ctx.sizeBlock = 64
    ctx.sizeDigest = 20
  elif T is ripemd256:
    ctx.state[0] = 0x67452301'u32
    ctx.state[1] = 0xEFCDAB89'u32
    ctx.state[2] = 0x98BADCFE'u32
    ctx.state[3] = 0x10325476'u32
    ctx.state[4] = 0x76543210'u32
    ctx.state[5] = 0xFEDCBA98'u32
    ctx.state[6] = 0x89ABCDEF'u32
    ctx.state[7] = 0x01234567'u32
    ctx.sizeBlock = 64
    ctx.sizeDigest = 32
  else:
    ctx.state[0] = 0x67452301'u32
    ctx.state[1] = 0xEFCDAB89'u32
    ctx.state[2] = 0x98BADCFE'u32
    ctx.state[3] = 0x10325476'u32
    ctx.state[4] = 0xC3D2E1F0'u32
    ctx.state[5] = 0x76543210'u32
    ctx.state[6] = 0xFEDCBA98'u32
    ctx.state[7] = 0x89ABCDEF'u32
    ctx.state[8] = 0x01234567'u32
    ctx.state[9] = 0x3C2D1E0F'u32
    ctx.sizeBlock = 64
    ctx.sizeDigest = 40

proc update*[T: ripemd](ctx: T, data: ptr uint8, ulen: uint) =
  var pos = 0'u
  var length = ulen

  while length > 0'u:
    let offset = uint(ctx.count[0] and 0x3F)
    let size = min(64'u - offset, length)
    copyMem(addr(ctx.buffer[offset]),
            cast[pointer](cast[uint](data) + pos), size)
    pos = pos + size
    length = length - size
    ctx.count[0] += uint32(size)
    if ctx.count[0] < uint32(size):
      ctx.count[1] += 1'u32
    if (ctx.count[0] and 0x3F) == 0:
      when T is ripemd128:
        ripemd128Transform(ctx.state, addr(ctx.buffer[0]))
      elif T is ripemd160:
        ripemd160Transform(ctx.state, addr(ctx.buffer[0]))
      elif T is ripemd256:
        ripemd256Transform(ctx.state, addr(ctx.buffer[0]))
      else:
        ripemd320Transform(ctx.state, addr(ctx.buffer[0]))

proc finalize[T: ripemd](ctx: T) =
  let size = (ctx.count[0] and 0x3F)
  var buffer = addr(ctx.buffer[0])
  zeroMem(addr(ctx.buffer[size]), 0x40'u - size)
  ctx.buffer[size] = 0x80
  if size > 55'u32:
    when T is ripemd128:
      ripemd128Transform(ctx.state, addr(ctx.buffer[0]))
    elif T is ripemd160:
      ripemd160Transform(ctx.state, addr(ctx.buffer[0]))
    elif T is ripemd256:
      ripemd256Transform(ctx.state, addr(ctx.buffer[0]))
    else:
      ripemd320Transform(ctx.state, addr(ctx.buffer[0]))
    zeroMem(addr(ctx.buffer[0]), 0x40)
  SET_DWORD(buffer, 14, (ctx.count[0]) shl 3)
  SET_DWORD(buffer, 15, (ctx.count[0] shr 29) or (ctx.count[1] shl 3))
  when T is ripemd128:
    ripemd128Transform(ctx.state, addr(ctx.buffer[0]))
  elif T is ripemd160:
    ripemd160Transform(ctx.state, addr(ctx.buffer[0]))
  elif T is ripemd256:
    ripemd256Transform(ctx.state, addr(ctx.buffer[0]))
  else:
    ripemd320Transform(ctx.state, addr(ctx.buffer[0]))

proc finish*[T: ripemd](ctx: T, data: ptr uint8, ulen: uint): uint =
  result = 0
  finalize(ctx)
  when T is ripemd128:
    if ulen >= 16'u:
      result = 16
      for i in 0..3:
        SET_DWORD(data, i, BSWAP(ctx.state[i]))
  elif T is ripemd160:
    if ulen >= 20'u:
      result = 20
      for i in 0..4:
        SET_DWORD(data, i, BSWAP(ctx.state[i]))
  elif T is ripemd256:
    if ulen >= 32'u:
      result = 32
      for i in 0..7:
        SET_DWORD(data, i, BSWAP(ctx.state[i]))
  else:
    if ulen >= 40'u:
      result = 40
      for i in 0..9:
        SET_DWORD(data, i, BSWAP(ctx.state[i]))

proc finish*[T: ripemd](ctx: T): MdDigest =
  result = MdDigest()
  result.size = finish(ctx, cast[ptr uint8](addr result.data[0]),
                       MaxMdDigestLength)
