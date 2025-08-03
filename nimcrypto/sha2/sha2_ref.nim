#
#
#                    NimCrypto
#        (c) Copyright 2016-2025 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

import ".."/[hash, utils]
import "."/[sha2_common]
export hash

const
  SHA2_REF_sha256Compress* = true
  SHA2_REF_sha512Compress* = true

template ROUND256(a, b, c, d, e, f, g, h, z) =
  t0 = h + TAU1(e) + CH0(e, f, g) + K0[z] + W[z]
  t1 = TAU0(a) + MAJ0(a, b, c)
  d = d + t0
  h = t0 + t1

template ROUND512(a, b, c, d, e, f, g, h, z) =
  t0 = h + PHI1(e) + CH1(e, f, g) + K1[z] + W[z]
  t1 = PHI0(a) + MAJ1(a, b, c)
  d = d + t0
  h = t0 + t1

template WMIX256(i) =
  W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16]

template WMIX512(i) =
  W[i] = RHO1(W[i - 2]) + W[i - 7] + RHO0(W[i - 15]) + W[i - 16]

template WLOOP256() =
  WMIX256(16); WMIX256(17); WMIX256(18); WMIX256(19);
  WMIX256(20); WMIX256(21); WMIX256(22); WMIX256(23);
  WMIX256(24); WMIX256(25); WMIX256(26); WMIX256(27);
  WMIX256(28); WMIX256(29); WMIX256(30); WMIX256(31);
  WMIX256(32); WMIX256(33); WMIX256(34); WMIX256(35);
  WMIX256(36); WMIX256(37); WMIX256(38); WMIX256(39);
  WMIX256(40); WMIX256(41); WMIX256(42); WMIX256(43);
  WMIX256(44); WMIX256(45); WMIX256(46); WMIX256(47);
  WMIX256(48); WMIX256(49); WMIX256(50); WMIX256(51);
  WMIX256(52); WMIX256(53); WMIX256(54); WMIX256(55);
  WMIX256(56); WMIX256(57); WMIX256(58); WMIX256(59);
  WMIX256(60); WMIX256(61); WMIX256(62); WMIX256(63);

template WLOOP512() =
  WMIX512(16); WMIX512(17); WMIX512(18); WMIX512(19);
  WMIX512(20); WMIX512(21); WMIX512(22); WMIX512(23);
  WMIX512(24); WMIX512(25); WMIX512(26); WMIX512(27);
  WMIX512(28); WMIX512(29); WMIX512(30); WMIX512(31);
  WMIX512(32); WMIX512(33); WMIX512(34); WMIX512(35);
  WMIX512(36); WMIX512(37); WMIX512(38); WMIX512(39);
  WMIX512(40); WMIX512(41); WMIX512(42); WMIX512(43);
  WMIX512(44); WMIX512(45); WMIX512(46); WMIX512(47);
  WMIX512(48); WMIX512(49); WMIX512(50); WMIX512(51);
  WMIX512(52); WMIX512(53); WMIX512(54); WMIX512(55);
  WMIX512(56); WMIX512(57); WMIX512(58); WMIX512(59);
  WMIX512(60); WMIX512(61); WMIX512(62); WMIX512(63);
  WMIX512(64); WMIX512(65); WMIX512(66); WMIX512(67);
  WMIX512(68); WMIX512(69); WMIX512(70); WMIX512(71);
  WMIX512(72); WMIX512(73); WMIX512(74); WMIX512(75);
  WMIX512(76); WMIX512(77); WMIX512(78); WMIX512(79);

func sha256Compress*(
    state: var array[8, uint32],
    data: openArray[byte],
    blocks: int
) {.noinit.} =
  var
    W {.align(16), noinit.}: array[64, uint32]
    t0, t1: uint32
    blocksCount = blocks
    offset = 0

  while blocksCount > 0:
    W[0] = beLoad32(data, offset + 0); W[1] = beLoad32(data, offset + 4);
    W[2] = beLoad32(data, offset + 8); W[3] = beLoad32(data, offset + 12)
    W[4] = beLoad32(data, offset + 16); W[5] = beLoad32(data, offset + 20)
    W[6] = beLoad32(data, offset + 24); W[7] = beLoad32(data, offset + 28)
    W[8] = beLoad32(data, offset + 32); W[9] = beLoad32(data, offset + 36)
    W[10] = beLoad32(data, offset + 40); W[11] = beLoad32(data, offset + 44)
    W[12] = beLoad32(data, offset + 48); W[13] = beLoad32(data, offset + 52)
    W[14] = beLoad32(data, offset + 56); W[15] = beLoad32(data, offset + 60)

    WLOOP256()

    var
      s0 = state[0]
      s1 = state[1]
      s2 = state[2]
      s3 = state[3]
      s4 = state[4]
      s5 = state[5]
      s6 = state[6]
      s7 = state[7]

    ROUND256(s0, s1, s2, s3, s4, s5, s6, s7, 0)
    ROUND256(s7, s0, s1, s2, s3, s4, s5, s6, 1)
    ROUND256(s6, s7, s0, s1, s2, s3, s4, s5, 2)
    ROUND256(s5, s6, s7, s0, s1, s2, s3, s4, 3)
    ROUND256(s4, s5, s6, s7, s0, s1, s2, s3, 4)
    ROUND256(s3, s4, s5, s6, s7, s0, s1, s2, 5)
    ROUND256(s2, s3, s4, s5, s6, s7, s0, s1, 6)
    ROUND256(s1, s2, s3, s4, s5, s6, s7, s0, 7)
    ROUND256(s0, s1, s2, s3, s4, s5, s6, s7, 8)
    ROUND256(s7, s0, s1, s2, s3, s4, s5, s6, 9)
    ROUND256(s6, s7, s0, s1, s2, s3, s4, s5, 10)
    ROUND256(s5, s6, s7, s0, s1, s2, s3, s4, 11)
    ROUND256(s4, s5, s6, s7, s0, s1, s2, s3, 12)
    ROUND256(s3, s4, s5, s6, s7, s0, s1, s2, 13)
    ROUND256(s2, s3, s4, s5, s6, s7, s0, s1, 14)
    ROUND256(s1, s2, s3, s4, s5, s6, s7, s0, 15)

    ROUND256(s0, s1, s2, s3, s4, s5, s6, s7, 16)
    ROUND256(s7, s0, s1, s2, s3, s4, s5, s6, 17)
    ROUND256(s6, s7, s0, s1, s2, s3, s4, s5, 18)
    ROUND256(s5, s6, s7, s0, s1, s2, s3, s4, 19)
    ROUND256(s4, s5, s6, s7, s0, s1, s2, s3, 20)
    ROUND256(s3, s4, s5, s6, s7, s0, s1, s2, 21)
    ROUND256(s2, s3, s4, s5, s6, s7, s0, s1, 22)
    ROUND256(s1, s2, s3, s4, s5, s6, s7, s0, 23)
    ROUND256(s0, s1, s2, s3, s4, s5, s6, s7, 24)
    ROUND256(s7, s0, s1, s2, s3, s4, s5, s6, 25)
    ROUND256(s6, s7, s0, s1, s2, s3, s4, s5, 26)
    ROUND256(s5, s6, s7, s0, s1, s2, s3, s4, 27)
    ROUND256(s4, s5, s6, s7, s0, s1, s2, s3, 28)
    ROUND256(s3, s4, s5, s6, s7, s0, s1, s2, 29)
    ROUND256(s2, s3, s4, s5, s6, s7, s0, s1, 30)
    ROUND256(s1, s2, s3, s4, s5, s6, s7, s0, 31)

    ROUND256(s0, s1, s2, s3, s4, s5, s6, s7, 32)
    ROUND256(s7, s0, s1, s2, s3, s4, s5, s6, 33)
    ROUND256(s6, s7, s0, s1, s2, s3, s4, s5, 34)
    ROUND256(s5, s6, s7, s0, s1, s2, s3, s4, 35)
    ROUND256(s4, s5, s6, s7, s0, s1, s2, s3, 36)
    ROUND256(s3, s4, s5, s6, s7, s0, s1, s2, 37)
    ROUND256(s2, s3, s4, s5, s6, s7, s0, s1, 38)
    ROUND256(s1, s2, s3, s4, s5, s6, s7, s0, 39)
    ROUND256(s0, s1, s2, s3, s4, s5, s6, s7, 40)
    ROUND256(s7, s0, s1, s2, s3, s4, s5, s6, 41)
    ROUND256(s6, s7, s0, s1, s2, s3, s4, s5, 42)
    ROUND256(s5, s6, s7, s0, s1, s2, s3, s4, 43)
    ROUND256(s4, s5, s6, s7, s0, s1, s2, s3, 44)
    ROUND256(s3, s4, s5, s6, s7, s0, s1, s2, 45)
    ROUND256(s2, s3, s4, s5, s6, s7, s0, s1, 46)
    ROUND256(s1, s2, s3, s4, s5, s6, s7, s0, 47)

    ROUND256(s0, s1, s2, s3, s4, s5, s6, s7, 48)
    ROUND256(s7, s0, s1, s2, s3, s4, s5, s6, 49)
    ROUND256(s6, s7, s0, s1, s2, s3, s4, s5, 50)
    ROUND256(s5, s6, s7, s0, s1, s2, s3, s4, 51)
    ROUND256(s4, s5, s6, s7, s0, s1, s2, s3, 52)
    ROUND256(s3, s4, s5, s6, s7, s0, s1, s2, 53)
    ROUND256(s2, s3, s4, s5, s6, s7, s0, s1, 54)
    ROUND256(s1, s2, s3, s4, s5, s6, s7, s0, 55)
    ROUND256(s0, s1, s2, s3, s4, s5, s6, s7, 56)
    ROUND256(s7, s0, s1, s2, s3, s4, s5, s6, 57)
    ROUND256(s6, s7, s0, s1, s2, s3, s4, s5, 58)
    ROUND256(s5, s6, s7, s0, s1, s2, s3, s4, 59)
    ROUND256(s4, s5, s6, s7, s0, s1, s2, s3, 60)
    ROUND256(s3, s4, s5, s6, s7, s0, s1, s2, 61)
    ROUND256(s2, s3, s4, s5, s6, s7, s0, s1, 62)
    ROUND256(s1, s2, s3, s4, s5, s6, s7, s0, 63)

    state[0] = state[0] + s0
    state[1] = state[1] + s1
    state[2] = state[2] + s2
    state[3] = state[3] + s3
    state[4] = state[4] + s4
    state[5] = state[5] + s5
    state[6] = state[6] + s6
    state[7] = state[7] + s7

    offset += sha256.sizeBlock()
    dec(blocksCount)

func sha512Compress*(
    state: var array[8, uint64],
    data: openArray[byte],
    blocks: int
) {.noinit.} =
  var
    W {.align(16), noinit.}: array[80, uint64]
    t0, t1: uint64
    blocksCount = blocks
    offset = 0

  while blocksCount > 0:
    W[0] = beLoad64(data, offset + 0); W[1] = beLoad64(data, offset + 8);
    W[2] = beLoad64(data, offset + 16); W[3] = beLoad64(data, offset + 24)
    W[4] = beLoad64(data, offset + 32); W[5] = beLoad64(data, offset + 40)
    W[6] = beLoad64(data, offset + 48); W[7] = beLoad64(data, offset + 56)
    W[8] = beLoad64(data, offset + 64); W[9] = beLoad64(data, offset + 72)
    W[10] = beLoad64(data, offset + 80); W[11] = beLoad64(data, offset + 88)
    W[12] = beLoad64(data, offset + 96); W[13] = beLoad64(data, offset + 104)
    W[14] = beLoad64(data, offset + 112); W[15] = beLoad64(data, offset + 120)

    WLOOP512()

    var s0 = state[0]
    var s1 = state[1]
    var s2 = state[2]
    var s3 = state[3]
    var s4 = state[4]
    var s5 = state[5]
    var s6 = state[6]
    var s7 = state[7]

    ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 0)
    ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 1)
    ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 2)
    ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 3)
    ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 4)
    ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 5)
    ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 6)
    ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 7)
    ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 8)
    ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 9)
    ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 10)
    ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 11)
    ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 12)
    ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 13)
    ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 14)
    ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 15)

    ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 16)
    ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 17)
    ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 18)
    ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 19)
    ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 20)
    ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 21)
    ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 22)
    ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 23)
    ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 24)
    ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 25)
    ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 26)
    ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 27)
    ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 28)
    ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 29)
    ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 30)
    ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 31)

    ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 32)
    ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 33)
    ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 34)
    ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 35)
    ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 36)
    ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 37)
    ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 38)
    ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 39)
    ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 40)
    ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 41)
    ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 42)
    ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 43)
    ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 44)
    ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 45)
    ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 46)
    ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 47)

    ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 48)
    ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 49)
    ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 50)
    ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 51)
    ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 52)
    ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 53)
    ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 54)
    ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 55)
    ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 56)
    ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 57)
    ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 58)
    ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 59)
    ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 60)
    ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 61)
    ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 62)
    ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 63)

    ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 64)
    ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 65)
    ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 66)
    ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 67)
    ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 68)
    ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 69)
    ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 70)
    ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 71)
    ROUND512(s0, s1, s2, s3, s4, s5, s6, s7, 72)
    ROUND512(s7, s0, s1, s2, s3, s4, s5, s6, 73)
    ROUND512(s6, s7, s0, s1, s2, s3, s4, s5, 74)
    ROUND512(s5, s6, s7, s0, s1, s2, s3, s4, 75)
    ROUND512(s4, s5, s6, s7, s0, s1, s2, s3, 76)
    ROUND512(s3, s4, s5, s6, s7, s0, s1, s2, 77)
    ROUND512(s2, s3, s4, s5, s6, s7, s0, s1, 78)
    ROUND512(s1, s2, s3, s4, s5, s6, s7, s0, 79)

    state[0] = state[0] + s0
    state[1] = state[1] + s1
    state[2] = state[2] + s2
    state[3] = state[3] + s3
    state[4] = state[4] + s4
    state[5] = state[5] + s5
    state[6] = state[6] + s6
    state[7] = state[7] + s7

    offset += sha512.sizeBlock()
    dec(blocksCount)
