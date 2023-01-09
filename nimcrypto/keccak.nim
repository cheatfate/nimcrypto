#
#
#                    NimCrypto
#        (c) Copyright 2018 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements SHA3 (Secure Hash Algorithm 3) set of cryptographic
## hash functions designed by Guido Bertoni, Joan Daemen, Michaël Peeters and
## Gilles Van Assche.
##
## This module supports SHA3-224/256/384/512 and SHAKE-128/256.
##
## Tests for SHA3-224/256/384/512 made according to
## [https://www.di-mgt.com.au/sha_testvectors.html].
## Test for SHAKE-128/256 made according to
## [https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values#aHashing]
## 0bit and 1600bit test vectors used.
import hash, utils
export hash

{.deadCodeElim:on.}

const RNDC = [
  0x0000000000000001'u64, 0x0000000000008082'u64, 0x800000000000808A'u64,
  0x8000000080008000'u64, 0x000000000000808B'u64, 0x0000000080000001'u64,
  0x8000000080008081'u64, 0x8000000000008009'u64, 0x000000000000008A'u64,
  0x0000000000000088'u64, 0x0000000080008009'u64, 0x000000008000000A'u64,
  0x000000008000808B'u64, 0x800000000000008B'u64, 0x8000000000008089'u64,
  0x8000000000008003'u64, 0x8000000000008002'u64, 0x8000000000000080'u64,
  0x000000000000800A'u64, 0x800000008000000A'u64, 0x8000000080008081'u64,
  0x8000000000008080'u64, 0x0000000080000001'u64, 0x8000000080008008'u64
]

type
  KeccakKind* = enum
    Sha3, Keccak, Shake

  KeccakContext*[bits: static[int],
                 kind: static[KeccakKind]] = object
    q: array[25 * 8, byte]
    pt: int

  keccak224* = KeccakContext[224, Keccak]
  keccak256* = KeccakContext[256, Keccak]
  keccak384* = KeccakContext[384, Keccak]
  keccak512* = KeccakContext[512, Keccak]
  sha3_224* = KeccakContext[224, Sha3]
  sha3_256* = KeccakContext[256, Sha3]
  sha3_384* = KeccakContext[384, Sha3]
  sha3_512* = KeccakContext[512, Sha3]
  shake128* = KeccakContext[128, Shake]
  shake256* = KeccakContext[256, Shake]
  keccak* = keccak224 | keccak256 | keccak384 | keccak512 |
            sha3_224 | sha3_256 | sha3_384 | sha3_512

# This difference in implementation was made because Nim VM do not support more
# then 256 registers and so it is not enough for it to perform round in
# template.
when nimvm:
  proc THETA1(a: var openArray[uint64], b: openArray[uint64],
              c: int) {.inline.} =
    a[c] = b[c] xor b[c + 5] xor b[c + 10] xor b[c + 15] xor b[c + 20]

  proc THETA2(a: var uint64, b: openArray[uint64], c: int) {.inline.} =
    a = b[(c + 4) mod 5] xor ROL(uint64(b[(c + 1) mod 5]), 1)

  proc THETA3(a: var openArray[uint64], b: int, c: uint64) {.inline.} =
    a[b] = a[b] xor c
    a[b + 5] = a[b + 5] xor c
    a[b + 10] = a[b + 10] xor c
    a[b + 15] = a[b + 15] xor c
    a[b + 20] = a[b + 20] xor c

  proc RHOPI(a: var openArray[uint64], b: var openArray[uint64], c: var uint64,
             d, e: int) {.inline.} =
    a[0] = b[d]
    b[d] = ROL(c, e)
    c = uint64(a[0])

  proc CHI(a: var openArray[uint64], b: var openArray[uint64],
           c: int) {.inline.} =
    a[0] = b[c]
    a[1] = b[c + 1]
    a[2] = b[c + 2]
    a[3] = b[c + 3]
    a[4] = b[c + 4]
    b[c] = b[c] xor (not(a[1]) and a[2])
    b[c + 1] = b[c + 1] xor (not(a[2]) and a[3])
    b[c + 2] = b[c + 2] xor (not(a[3]) and a[4])
    b[c + 3] = b[c + 3] xor (not(a[4]) and a[0])
    b[c + 4] = b[c + 4] xor (not(a[0]) and a[1])


  proc KECCAKROUNDP(a: var openArray[uint64], b: var openArray[uint64],
                    c: var uint64, r: int) {.inline.} =
    THETA1(b, a, 0)
    THETA1(b, a, 1)
    THETA1(b, a, 2)
    THETA1(b, a, 3)
    THETA1(b, a, 4)

    THETA2(c, b, 0)
    THETA3(a, 0, c)
    THETA2(c, b, 1)
    THETA3(a, 1, c)
    THETA2(c, b, 2)
    THETA3(a, 2, c)
    THETA2(c, b, 3)
    THETA3(a, 3, c)
    THETA2(c, b, 4)
    THETA3(a, 4, c)

    c = a[1]
    RHOPI(b, a, c, 10, 1)
    RHOPI(b, a, c, 7, 3)
    RHOPI(b, a, c, 11, 6)
    RHOPI(b, a, c, 17, 10)
    RHOPI(b, a, c, 18, 15)
    RHOPI(b, a, c, 3, 21)
    RHOPI(b, a, c, 5, 28)
    RHOPI(b, a, c, 16, 36)
    RHOPI(b, a, c, 8, 45)
    RHOPI(b, a, c, 21, 55)
    RHOPI(b, a, c, 24, 2)
    RHOPI(b, a, c, 4, 14)
    RHOPI(b, a, c, 15, 27)
    RHOPI(b, a, c, 23, 41)
    RHOPI(b, a, c, 19, 56)
    RHOPI(b, a, c, 13, 8)
    RHOPI(b, a, c, 12, 25)
    RHOPI(b, a, c, 2, 43)
    RHOPI(b, a, c, 20, 62)
    RHOPI(b, a, c, 14, 18)
    RHOPI(b, a, c, 22, 39)
    RHOPI(b, a, c, 9, 61)
    RHOPI(b, a, c, 6, 20)
    RHOPI(b, a, c, 1, 44)

    CHI(b, a, 0)
    CHI(b, a, 5)
    CHI(b, a, 10)
    CHI(b, a, 15)
    CHI(b, a, 20)

    a[0] = a[0] xor RNDC[r]

else:
  template THETA1(a, b, c: untyped) =
    a[c] = b[c] xor b[c + 5] xor b[c + 10] xor b[c + 15] xor b[c + 20]

  template THETA2(a, b, c: untyped) =
    a = b[(c + 4) mod 5] xor ROL(uint64(b[(c + 1) mod 5]), 1)

  template THETA3(a, b, c) =
    a[b] = a[b] xor c
    a[b + 5] = a[b + 5] xor c
    a[b + 10] = a[b + 10] xor c
    a[b + 15] = a[b + 15] xor c
    a[b + 20] = a[b + 20] xor c

  template RHOPI(a, b, c, d, e) =
    a[0] = b[d]
    b[d] = ROL(c, e)
    c = a[0]

  template CHI(a, b, c) =
    a[0] = b[c]
    a[1] = b[c + 1]
    a[2] = b[c + 2]
    a[3] = b[c + 3]
    a[4] = b[c + 4]
    b[c] = b[c] xor (not(a[1]) and a[2])
    b[c + 1] = b[c + 1] xor (not(a[2]) and a[3])
    b[c + 2] = b[c + 2] xor (not(a[3]) and a[4])
    b[c + 3] = b[c + 3] xor (not(a[4]) and a[0])
    b[c + 4] = b[c + 4] xor (not(a[0]) and a[1])

  template KECCAKROUND(a, b, c, r) =
    THETA1(b, a, 0)
    THETA1(b, a, 1)
    THETA1(b, a, 2)
    THETA1(b, a, 3)
    THETA1(b, a, 4)

    THETA2(c, b, 0)
    THETA3(a, 0, c)
    THETA2(c, b, 1)
    THETA3(a, 1, c)
    THETA2(c, b, 2)
    THETA3(a, 2, c)
    THETA2(c, b, 3)
    THETA3(a, 3, c)
    THETA2(c, b, 4)
    THETA3(a, 4, c)

    c = a[1]
    RHOPI(b, a, c, 10, 1)
    RHOPI(b, a, c, 7, 3)
    RHOPI(b, a, c, 11, 6)
    RHOPI(b, a, c, 17, 10)
    RHOPI(b, a, c, 18, 15)
    RHOPI(b, a, c, 3, 21)
    RHOPI(b, a, c, 5, 28)
    RHOPI(b, a, c, 16, 36)
    RHOPI(b, a, c, 8, 45)
    RHOPI(b, a, c, 21, 55)
    RHOPI(b, a, c, 24, 2)
    RHOPI(b, a, c, 4, 14)
    RHOPI(b, a, c, 15, 27)
    RHOPI(b, a, c, 23, 41)
    RHOPI(b, a, c, 19, 56)
    RHOPI(b, a, c, 13, 8)
    RHOPI(b, a, c, 12, 25)
    RHOPI(b, a, c, 2, 43)
    RHOPI(b, a, c, 20, 62)
    RHOPI(b, a, c, 14, 18)
    RHOPI(b, a, c, 22, 39)
    RHOPI(b, a, c, 9, 61)
    RHOPI(b, a, c, 6, 20)
    RHOPI(b, a, c, 1, 44)

    CHI(b, a, 0)
    CHI(b, a, 5)
    CHI(b, a, 10)
    CHI(b, a, 15)
    CHI(b, a, 20)

    a[0] = a[0] xor RNDC[r]

proc keccakTransform(data: var array[200, byte]) {.inline.} =
  var
    bc {.noinit.}: array[5, uint64]
    st {.noinit.}: array[25, uint64]
    t: uint64

  when nimvm:
    for i in 0 ..< len(st):
      st[i] = leLoad64(data, i * 8)
  else:
    st[0] = leLoad64(data, 0)
    st[1] = leLoad64(data, 8)
    st[2] = leLoad64(data, 16)
    st[3] = leLoad64(data, 24)
    st[4] = leLoad64(data, 32)
    st[5] = leLoad64(data, 40)
    st[6] = leLoad64(data, 48)
    st[7] = leLoad64(data, 56)
    st[8] = leLoad64(data, 64)
    st[9] = leLoad64(data, 72)
    st[10] = leLoad64(data, 80)
    st[11] = leLoad64(data, 88)
    st[12] = leLoad64(data, 96)
    st[13] = leLoad64(data, 104)
    st[14] = leLoad64(data, 112)
    st[15] = leLoad64(data, 120)
    st[16] = leLoad64(data, 128)
    st[17] = leLoad64(data, 136)
    st[18] = leLoad64(data, 144)
    st[19] = leLoad64(data, 152)
    st[20] = leLoad64(data, 160)
    st[21] = leLoad64(data, 168)
    st[22] = leLoad64(data, 176)
    st[23] = leLoad64(data, 184)
    st[24] = leLoad64(data, 192)

  when nimvm:
    for i in 0..23:
      KECCAKROUNDP(st, bc, t, i)
  else:
    KECCAKROUND(st, bc, t, 0)
    KECCAKROUND(st, bc, t, 1)
    KECCAKROUND(st, bc, t, 2)
    KECCAKROUND(st, bc, t, 3)
    KECCAKROUND(st, bc, t, 4)
    KECCAKROUND(st, bc, t, 5)
    KECCAKROUND(st, bc, t, 6)
    KECCAKROUND(st, bc, t, 7)
    KECCAKROUND(st, bc, t, 8)
    KECCAKROUND(st, bc, t, 9)
    KECCAKROUND(st, bc, t, 10)
    KECCAKROUND(st, bc, t, 11)
    KECCAKROUND(st, bc, t, 12)
    KECCAKROUND(st, bc, t, 13)
    KECCAKROUND(st, bc, t, 14)
    KECCAKROUND(st, bc, t, 15)
    KECCAKROUND(st, bc, t, 16)
    KECCAKROUND(st, bc, t, 17)
    KECCAKROUND(st, bc, t, 18)
    KECCAKROUND(st, bc, t, 19)
    KECCAKROUND(st, bc, t, 20)
    KECCAKROUND(st, bc, t, 21)
    KECCAKROUND(st, bc, t, 22)
    KECCAKROUND(st, bc, t, 23)

  when nimvm:
    for i in 0 ..< len(st):
      leStore64(data, i * 8, st[i])
  else:
    leStore64(data, 0, st[0])
    leStore64(data, 8, st[1])
    leStore64(data, 16, st[2])
    leStore64(data, 24, st[3])
    leStore64(data, 32, st[4])
    leStore64(data, 40, st[5])
    leStore64(data, 48, st[6])
    leStore64(data, 56, st[7])
    leStore64(data, 64, st[8])
    leStore64(data, 72, st[9])
    leStore64(data, 80, st[10])
    leStore64(data, 88, st[11])
    leStore64(data, 96, st[12])
    leStore64(data, 104, st[13])
    leStore64(data, 112, st[14])
    leStore64(data, 120, st[15])
    leStore64(data, 128, st[16])
    leStore64(data, 136, st[17])
    leStore64(data, 144, st[18])
    leStore64(data, 152, st[19])
    leStore64(data, 160, st[20])
    leStore64(data, 168, st[21])
    leStore64(data, 176, st[22])
    leStore64(data, 184, st[23])
    leStore64(data, 192, st[24])

template sizeDigest*(ctx: KeccakContext): uint =
  (ctx.bits div 8)

template sizeBlock*(ctx: KeccakContext): uint =
  (200)

template rsize(ctx: KeccakContext): int =
  200 - 2 * (ctx.bits div 8)

template sizeDigest*(r: typedesc[keccak | shake128 | shake256]): int =
  when r is shake128:
    (16)
  elif r is keccak224 or r is sha3_224:
    (28)
  elif r is keccak256 or r is sha3_256 or r is shake256:
    (32)
  elif r is keccak384 or r is sha3_384:
    (48)
  elif r is keccak512 or r is sha3_512:
    (64)

template sizeBlock*(r: typedesc[keccak | shake128 | shake256]): int =
  (200)

proc init*(ctx: var KeccakContext) {.inline.} =
  ctx = type(ctx)()

proc clear*(ctx: var KeccakContext) {.inline.} =
  when nimvm:
    for i in 0 ..< len(ctx.q):
      ctx.q[i] = 0'u8
    ctx.pt = 0
  else:
    burnMem(ctx)

proc reset*(ctx: var KeccakContext) {.inline.} =
  init(ctx)

proc update*[T: bchar](ctx: var KeccakContext,
                       data: openArray[T]) {.inline.} =
  var j = ctx.pt
  if len(data) > 0:
    for i in 0 ..< len(data):
      when T is byte:
        ctx.q[j] = ctx.q[j] xor data[i]
      else:
        ctx.q[j] = ctx.q[j] xor byte(data[i])
      inc(j)
      if j >= ctx.rsize:
        keccakTransform(ctx.q)
        j = 0
    ctx.pt = j

proc update*(ctx: var KeccakContext, pbytes: ptr byte,
             nbytes: uint) {.inline.} =
  var p = cast[ptr UncheckedArray[byte]](pbytes)
  ctx.update(toOpenArray(p, 0, int(nbytes) - 1))

proc xof*(ctx: var KeccakContext) {.inline.} =
  when ctx.kind != Shake:
    {.error: "Only `Shake128` and `Shake256` types are supported".}
  ctx.q[ctx.pt] = ctx.q[ctx.pt] xor 0x1F'u8
  ctx.q[ctx.rsize - 1] = ctx.q[ctx.rsize - 1] xor 0x80'u8
  keccakTransform(ctx.q)
  ctx.pt = 0

proc output*(ctx: var KeccakContext,
             data: var openArray[byte]): uint {.inline.} =
  when ctx.kind != Shake:
    {.error: "Only `Shake128` and `Shake256` types are supported".}
  var j = ctx.pt
  if len(data) > 0:
    for i in 0 ..< len(data):
      if j >= ctx.rsize:
        keccakTransform(ctx.q)
        j = 0
      data[i] = ctx.q[j]
      inc(j)
    ctx.pt = j
    result = uint(len(data))

proc output*(ctx: var KeccakContext, pbytes: ptr byte,
             nbytes: uint): uint {.inline.} =
  var ptrarr = cast[ptr UncheckedArray[byte]](pbytes)
  result = ctx.output(ptrarr.toOpenArray(0, int(nbytes) - 1))

proc finish*(ctx: var KeccakContext,
             data: var openArray[byte]): uint {.inline, discardable.} =
  when ctx.kind == Sha3:
    ctx.q[ctx.pt] = ctx.q[ctx.pt] xor 0x06'u8
  else:
    ctx.q[ctx.pt] = ctx.q[ctx.pt] xor 0x01'u8
  ctx.q[ctx.rsize - 1] = ctx.q[ctx.rsize - 1] xor 0x80'u8
  keccakTransform(ctx.q)
  if len(data) >= int(ctx.sizeDigest):
    for i in 0 ..< int(ctx.sizeDigest):
      data[i] = ctx.q[i]
    result = ctx.sizeDigest

proc finish*(ctx: var KeccakContext, pbytes: ptr byte,
             nbytes: uint): uint {.inline.} =
  var ptrarr = cast[ptr UncheckedArray[byte]](pbytes)
  result = ctx.finish(ptrarr.toOpenArray(0, int(nbytes) - 1))

proc finish*(ctx: var KeccakContext): MDigest[ctx.bits] {.inline.} =
  discard finish(ctx, result.data)
