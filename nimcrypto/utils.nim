#
#
#                    NimCrypto
#        (c) Copyright 2016 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module utility functions.

{.deadCodeElim:on.}

proc ROL*[T: uint32|uint64](x: T, n: int): T {.inline.} =
  when T is uint32:
    result = (x shl T(n and 0x1F)) or (x shr T(8 * sizeof(T) - (n and 0x1F)))
  else:
    result = (x shl T(n and 0x3F)) or (x shr T(8 * sizeof(T) - (n and 0x3F)))

proc ROR*[T: uint32|uint64](x: T, n: int): T {.inline.} =
  when T is uint32:
    result = (x shr T(n and 0x1F)) or (x shl T(8 * sizeof(T) - (n and 0x1F)))
  else:
    result = (x shr T(n and 0x3F)) or (x shl T(8 * sizeof(T) - (n and 0x3F)))

template GETU32*(p, o): uint32 =
  (uint32(cast[ptr uint8](cast[uint](p) + o)[]) shl 24) xor
    (uint32(cast[ptr uint8](cast[uint](p) + (o + 1))[]) shl 16) xor
    (uint32(cast[ptr uint8](cast[uint](p) + (o + 2))[]) shl 8) xor
    (uint32(cast[ptr uint8](cast[uint](p) + (o + 3))[]))

template GETU64*(p, o): uint64 =
  (uint64(cast[ptr uint8](cast[uint](p) + o)[]) shl 56) xor
    (uint64(cast[ptr uint8](cast[uint](p) + (o + 1))[]) shl 48) xor
    (uint64(cast[ptr uint8](cast[uint](p) + (o + 2))[]) shl 40) xor
    (uint64(cast[ptr uint8](cast[uint](p) + (o + 3))[]) shl 32) xor
    (uint64(cast[ptr uint8](cast[uint](p) + (o + 4))[]) shl 24) xor
    (uint64(cast[ptr uint8](cast[uint](p) + (o + 5))[]) shl 16) xor
    (uint64(cast[ptr uint8](cast[uint](p) + (o + 6))[]) shl 8) xor
    (uint64(cast[ptr uint8](cast[uint](p) + (o + 7))[]))

template PUTU32*(p, o, v) =
  cast[ptr uint8](cast[uint](p) + o)[] = cast[uint8](v shr 24)
  cast[ptr uint8](cast[uint](p) + o + 1)[] = cast[uint8](v shr 16)
  cast[ptr uint8](cast[uint](p) + o + 2)[] = cast[uint8](v shr 8)
  cast[ptr uint8](cast[uint](p) + o + 3)[] = cast[uint8](v)

template PUTU64*(p, o, v) =
  cast[ptr uint8](cast[uint](p) + o)[] = cast[uint8](v shr 56)
  cast[ptr uint8](cast[uint](p) + o + 1)[] = cast[uint8](v shr 48)
  cast[ptr uint8](cast[uint](p) + o + 2)[] = cast[uint8](v shr 40)
  cast[ptr uint8](cast[uint](p) + o + 3)[] = cast[uint8](v shr 32)
  cast[ptr uint8](cast[uint](p) + o + 4)[] = cast[uint8](v shr 24)
  cast[ptr uint8](cast[uint](p) + o + 5)[] = cast[uint8](v shr 16)
  cast[ptr uint8](cast[uint](p) + o + 6)[] = cast[uint8](v shr 8)
  cast[ptr uint8](cast[uint](p) + o + 7)[] = cast[uint8](v)

when cpuEndian == bigEndian:
  template BSWAP*[T: uint32|uint64](x: T): T =
    when T is uint32:
      ((ROR(x, 8) and 0xFF00FF00'u32) or (ROL(x, 8) and 0x00FF00FF'u32))
    else:
      ((x shl 56) or
        ((x shl 40) and 0xFF000000000000'u64) or
        ((x shl 24) and 0xFF0000000000'u64) or
        ((x shl 8) and 0xFF00000000'u64) or
        ((x shr 8) and 0xFF000000'u64) or
        ((x shr 24) and 0xFF0000'u64) or
        ((x shr 40) and 0xFF00'u64) or
        (x shr 56))
  template LSWAP*[T: uint32|uint64](x: T): T =
    x
  template EGETU32*(p, o): uint32 =
    GETU32(p, o)
  template EPUTU32*(p, o, v) =
    PUTU32(p, o, v)
else:
  template BSWAP*[T: uint32|uint64](x: T): T =
    x
  template LSWAP*[T: uint32|uint64](x: T): T =
    when T is uint32:
      ((ROR(x, 8) and 0xFF00FF00'u32) or (ROL(x, 8) and 0x00FF00FF'u32))
    else:
      ((x shl 56) or
        ((x shl 40) and 0xFF000000000000'u64) or
        ((x shl 24) and 0xFF0000000000'u64) or
        ((x shl 8) and 0xFF00000000'u64) or
        ((x shr 8) and 0xFF000000'u64) or
        ((x shr 24) and 0xFF0000'u64) or
        ((x shr 40) and 0xFF00'u64) or
        (x shr 56))
  template EGETU32*(p, o): uint32 =
    var tmp = GETU32(p, o)
    LSWAP[uint32](tmp)
  template EPUTU32*(p, o, v) =
    var tmp = LSWAP(v)
    PUTU32(p, o, tmp)

template GET_DWORD*(p: ptr uint8, i: int): uint32 =
  cast[ptr uint32](cast[uint](p) + (sizeof(uint32) * i).uint)[]

template SET_DWORD*(p: ptr uint8, i: int, v: uint32) =
  cast[ptr uint32](cast[uint](p) + (sizeof(uint32) * i).uint)[] = v

template GET_QWORD*(p: ptr uint8, i: int): uint64 =
  cast[ptr uint64](cast[uint](p) + (sizeof(uint64) * i).uint)[]

template SET_QWORD*(p: ptr uint8, i: int, v: uint64) =
  cast[ptr uint64](cast[uint](p) + (sizeof(uint64) * i).uint)[] = v

template GETU8*(p, o): uint8 =
  cast[ptr uint8](cast[uint](p) + uint(o))[]

template PUTU8*(p, o, v) =
  cast[ptr uint8](cast[uint](p) + uint(o))[] = v

proc fromHex*(a: string): seq[uint8] =
  doAssert(len(a) %% 2 == 0)
  if len(a) == 0:
    result = newSeq[uint8]()
  else:
    result = newSeq[uint8](len(a) div 2)
  var i = 0
  var k = 0
  var r = 0
  if len(a) > 0:
    while i < len(a):
      let c = a[i]
      if i != 0 and i %% 2 == 0:
        result[k] = r.uint8
        r = 0
        inc(k)
      else:
        r = r shl 4
      case c
      of 'a'..'f':
        r = r or (10 + ord(c) - ord('a'))
      of 'A'..'F':
        r = r or (10 + ord(c) - ord('A'))
      of '0'..'9':
        r = r or (ord(c) - ord('0'))
      else:
        doAssert(false)
      inc(i)
    result[k] = r.uint8

proc hexChar*(c: uint8): string =
  result = newString(2)
  let t1 = ord(c) shr 4
  let t0 = ord(c) and 0x0F
  case t1
  of 0..9: result[0] = chr(t1 + ord('0'))
  else: result[0] = chr(t1 - 10 + ord('A'))
  case t0:
  of 0..9: result[1] = chr(t0 + ord('0'))
  else: result[1] = chr(t0 - 10 + ord('A'))

proc toHex*(a: var openarray[uint8]): string =
  result = ""
  for i in a:
    result = result & hexChar(i)

proc stripSpaces*(s: string): string =
  result = ""
  let allowed:set[char] = {'A'..'Z', 'a'..'z', '0'..'9'}
  for i in s:
    if i in allowed:
      result &= i

proc burnMem*(p: pointer, size: Natural) =
  var sp {.volatile.} = cast[ptr uint8](p)
  var c = size
  if not isNil(sp):
    zeroMem(p, size)
    while c > 0:
      sp[] = 0
      sp = cast[ptr uint8](cast[uint](sp) + 1)
      dec(c)
