#
#
#                    NimCrypto
#        (c) Copyright 2016 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module provides utility functions common to all other submodules of
## nimcrypto.

{.deadCodeElim:on.}

template ROL*(x: uint32, n: int): uint32 =
  (x shl uint32(n and 0x1F)) or (x shr uint32(32 - (n and 0x1F)))

template ROL*(x: uint64, n: int): uint64 =
  (x shl uint64(n and 0x3F)) or (x shr uint64(64 - (n and 0x3F)))

template ROR*(x: uint32, n: int): uint32 =
  (x shr uint32(n and 0x1F)) or (x shl uint32(32 - (n and 0x1F)))

template ROR*(x: uint64, n: int): uint64 =
  (x shr uint64(n and 0x3F)) or (x shl uint64(64 - (n and 0x3F)))

template GETU32*(p, o): uint32 =
  (cast[uint32](cast[ptr byte](cast[uint](p) + o)[]) shl 24) xor
    (cast[uint32](cast[ptr byte](cast[uint](p) + (o + 1))[]) shl 16) xor
    (cast[uint32](cast[ptr byte](cast[uint](p) + (o + 2))[]) shl 8) xor
    (cast[uint32](cast[ptr byte](cast[uint](p) + (o + 3))[]))

template GETU64*(p, o): uint64 =
  (cast[uint64](cast[ptr byte](cast[uint](p) + o)[]) shl 56) xor
    (cast[uint64](cast[ptr byte](cast[uint](p) + (o + 1))[]) shl 48) xor
    (cast[uint64](cast[ptr byte](cast[uint](p) + (o + 2))[]) shl 40) xor
    (cast[uint64](cast[ptr byte](cast[uint](p) + (o + 3))[]) shl 32) xor
    (cast[uint64](cast[ptr byte](cast[uint](p) + (o + 4))[]) shl 24) xor
    (cast[uint64](cast[ptr byte](cast[uint](p) + (o + 5))[]) shl 16) xor
    (cast[uint64](cast[ptr byte](cast[uint](p) + (o + 6))[]) shl 8) xor
    (cast[uint64](cast[ptr byte](cast[uint](p) + (o + 7))[]))

template PUTU32*(p, o, v) =
  cast[ptr byte](cast[uint](p) + o)[] = cast[byte](v shr 24)
  cast[ptr byte](cast[uint](p) + o + 1)[] = cast[byte](v shr 16)
  cast[ptr byte](cast[uint](p) + o + 2)[] = cast[byte](v shr 8)
  cast[ptr byte](cast[uint](p) + o + 3)[] = cast[byte](v)

template PUTU64*(p, o, v) =
  cast[ptr byte](cast[uint](p) + o)[] = cast[byte](v shr 56)
  cast[ptr byte](cast[uint](p) + o + 1)[] = cast[byte](v shr 48)
  cast[ptr byte](cast[uint](p) + o + 2)[] = cast[byte](v shr 40)
  cast[ptr byte](cast[uint](p) + o + 3)[] = cast[byte](v shr 32)
  cast[ptr byte](cast[uint](p) + o + 4)[] = cast[byte](v shr 24)
  cast[ptr byte](cast[uint](p) + o + 5)[] = cast[byte](v shr 16)
  cast[ptr byte](cast[uint](p) + o + 6)[] = cast[byte](v shr 8)
  cast[ptr byte](cast[uint](p) + o + 7)[] = cast[byte](v)

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
    cast[ptr uint32]((cast[uint](p) + cast[uint](o)))[]
  template EPUTU32*(p, o, v) =
    cast[ptr uint32]((cast[uint](p) + cast[uint](o)))[] = v
  template EGETU64*(p, o): uint64 =
    cast[ptr uint64]((cast[uint](p) + cast[uint](o)))[]
  template EPUTU64*(p, o, v) =
    cast[ptr uint64]((cast[uint](p) + cast[uint](o)))[] = v
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
    GETU32(p, o)
  template EPUTU32*(p, o, v) =
    PUTU32(p, o, v)
  template EGETU64*(p, o): uint64 =
    GETU64(p, o)
  template EPUTU64*(p, o, v) =
    PUTU64(p, o, v)

template GET_DWORD*(p: ptr byte, i: int): uint32 =
  cast[ptr uint32](cast[uint](p) + cast[uint](sizeof(uint32) * i))[]

template SET_DWORD*(p: ptr byte, i: int, v: uint32) =
  cast[ptr uint32](cast[uint](p) + cast[uint](sizeof(uint32) * i))[] = v

template GET_QWORD*(p: ptr byte, i: int): uint64 =
  cast[ptr uint64](cast[uint](p) + cast[uint](sizeof(uint64) * i))[]

template SET_QWORD*(p: ptr byte, i: int, v: uint64) =
  cast[ptr uint64](cast[uint](p) + cast[uint](sizeof(uint64) * i))[] = v

template GETU8*(p, o): byte =
  cast[ptr byte](cast[uint](p) + cast[uint](o))[]

template PUTU8*(p, o, v) =
  cast[ptr byte](cast[uint](p) + cast[uint](o))[] = v

template skip0xPrefix(hexStr: string): int =
  ## Returns the index of the first meaningful char in `hexStr` by skipping
  ## "0x" prefix
  if hexStr.len == 0: 0
  elif hexStr[0] == '0' and hexStr[1] in {'x', 'X'}: 2
  else: 0

proc hexToBytes*(a: string, output: var openarray[byte]) =
  let offset = skip0xPrefix(a)
  let length = len(a) - offset
  if length > 2 * len(output):
    raise newException(ValueError, "Output buffer is too small")
  var i = offset
  var k = 0
  var r = 0
  if length > 0:
    while i < len(a):
      let c = a[i]
      if i != offset and i %% 2 == 0:
        output[k] = byte(r)
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
        raise newException(ValueError,
                           "Unexpected non-hex character \"" & $c & "\"")
      inc(i)
    output[k] = byte(r)

proc fromHex*(a: string): seq[byte] =
  if (len(a) mod 2) != 0:
    raise newException(ValueError, "Invalid hexadecimal string")
  if len(a) == 0:
    result = newSeq[byte]()
  else:
    let offset = skip0xPrefix(a)
    result = newSeq[byte]((len(a) - offset) div 2)
    hexToBytes(a, result)

proc hexChar*(c: byte, lowercase: bool = false): string =
  var alpha: int
  if lowercase:
    alpha = ord('a')
  else:
    alpha = ord('A')
  result = newString(2)
  let t1 = ord(c) shr 4
  let t0 = ord(c) and 0x0F
  case t1
  of 0..9: result[0] = chr(t1 + ord('0'))
  else: result[0] = chr(t1 - 10 + alpha)
  case t0:
  of 0..9: result[1] = chr(t0 + ord('0'))
  else: result[1] = chr(t0 - 10 + alpha)

proc toHex*(a: openarray[byte], lowercase: bool = false): string =
  result = ""
  for i in a:
    result = result & hexChar(i, lowercase)

proc stripSpaces*(s: string): string =
  result = ""
  const allowed:set[char] = {'A'..'Z', 'a'..'z', '0'..'9'}
  for i in s:
    if i in allowed:
      result &= i

proc burnMem*(p: pointer, size: Natural) =
  var sp {.volatile.} = cast[ptr byte](p)
  var c = size
  if not isNil(sp):
    zeroMem(p, size)
    while c > 0:
      sp[] = 0
      sp = cast[ptr byte](cast[uint](sp) + 1)
      dec(c)

proc burnArray*[T](a: var openarray[T]) {.inline.} =
  if len(a) > 0:
    burnMem(addr a[0], len(a) * sizeof(T))

template burnMem*[T](a: var seq[T]) =
  burnArray(a)

template burnMem*[A, B](a: var array[A, B]) =
  burnArray(a)

proc burnMem*[T](a: var T) {.inline.} =
  burnMem(addr a, sizeof(T))

proc isFullZero*(p: pointer, size: Natural): bool =
  result = true
  var counter = 0
  var sp {.volatile.} = cast[ptr byte](p)
  var c = size
  if not isNil(sp):
    while c > 0:
      if sp[] != 0'u8:
        counter += 1
      sp = cast[ptr byte](cast[uint](sp) + 1)
      dec(c)
  result = (counter == 0)

proc isFullZero*[T](a: openarray[T]): bool {.inline.} =
  result = true
  if len(a) > 0:
    result = isFullZero(unsafeAddr a[0], len(a) * sizeof(T))

proc isFullZero*[T](a: T): bool {.inline.} =
  result = isFullZero(unsafeAddr a, sizeof(T))

proc lit64ToCpu*(p: ptr byte, offset: int): uint64 {.deprecated, inline.} =
  ## Get uint64 integer from pointer ``p`` and offset ``o`` which must be
  ## stored in little-endian order.
  when cpuEndian == bigEndian:
    var pp = cast[ptr UncheckedArray[byte]](p)
    result = cast[uint64](pp[offset + 0] shl 56) or
             cast[uint64](pp[offset + 1] shl 48) or
             cast[uint64](pp[offset + 2] shl 40) or
             cast[uint64](pp[offset + 3] shl 32) or
             cast[uint64](pp[offset + 4] shl 24) or
             cast[uint64](pp[offset + 5] shl 16) or
             cast[uint64](pp[offset + 6] shl 8) or
             cast[uint64](pp[offset + 7])
  elif cpuEndian == littleEndian:
    result = cast[ptr uint64](cast[uint](p) + cast[uint](offset))[]

proc big64ToCpu*(p: ptr byte, offset: int): uint64 {.deprecated, inline.} =
  ## Get uint64 integer from pointer ``p`` and offset ``o`` which must be
  ## stored in big-endian order.
  when cpuEndian == bigEndian:
    result = cast[ptr uint64](cast[uint](p) + cast[uint](offset))[]
  else:
    var pp = cast[ptr UncheckedArray[byte]](p)
    result = cast[uint64](pp[offset + 0] shl 56) or
             cast[uint64](pp[offset + 1] shl 48) or
             cast[uint64](pp[offset + 2] shl 40) or
             cast[uint64](pp[offset + 3] shl 32) or
             cast[uint64](pp[offset + 4] shl 24) or
             cast[uint64](pp[offset + 5] shl 16) or
             cast[uint64](pp[offset + 6] shl 8) or
             cast[uint64](pp[offset + 7])

proc cpuToLit64*(p: ptr byte, offset: int, v: uint64) {.deprecated, inline.} =
  ## Store uint64 integer ``v`` to pointer ``p`` and offset ``o`` in
  ## little-endian order.
  when cpuEndian == bigEndian:
    var pp = cast[ptr UncheckedArray[byte]](p)
    pp[0] = cast[byte](v shr 56)
    pp[1] = cast[byte](v shr 48)
    pp[2] = cast[byte](v shr 40)
    pp[3] = cast[byte](v shr 32)
    pp[4] = cast[byte](v shr 24)
    pp[5] = cast[byte](v shr 16)
    pp[6] = cast[byte](v shr 8)
    pp[7] = cast[byte](v)
  elif cpuEndian == littleEndian:
    cast[ptr uint64](cast[uint](p) + cast[uint](offset))[] = v

proc cpuToBig64*(p: ptr byte, offset: int, v: uint64) {.deprecated, inline.} =
  ## Store uint64 integer ``v`` to pointer ``p`` and offset ``o`` in
  ## big-endian order.
  when cpuEndian == bigEndian:
    cast[ptr uint64](cast[uint](p) + cast[uint](offset))[] = v
  elif cpuEndian == littleEndian:
    var pp = cast[ptr UncheckedArray[byte]](p)
    pp[0] = cast[byte](v shr 56)
    pp[1] = cast[byte](v shr 48)
    pp[2] = cast[byte](v shr 40)
    pp[3] = cast[byte](v shr 32)
    pp[4] = cast[byte](v shr 24)
    pp[5] = cast[byte](v shr 16)
    pp[6] = cast[byte](v shr 8)
    pp[7] = cast[byte](v)

when defined(gcc) or defined(llvm_gcc) or defined(clang):
  func swapBytesBuiltin(x: uint8): uint8 = x
  func swapBytesBuiltin(x: uint16): uint16 {.
      importc: "__builtin_bswap16", nodecl.}
  func swapBytesBuiltin(x: uint32): uint32 {.
      importc: "__builtin_bswap32", nodecl.}
  func swapBytesBuiltin(x: uint64): uint64 {.
      importc: "__builtin_bswap64", nodecl.}

elif defined(icc):
  func swapBytesBuiltin(x: uint8): uint8 = x
  func swapBytesBuiltin(a: uint16): uint16 {.importc: "_bswap16", nodecl.}
  func swapBytesBuiltin(a: uint32): uint32 {.importc: "_bswap", nodec.}
  func swapBytesBuiltin(a: uint64): uint64 {.importc: "_bswap64", nodecl.}

elif defined(vcc):
  func swapBytesBuiltin(x: uint8): uint8 = x
  proc swapBytesBuiltin(a: uint16): uint16 {.
      importc: "_byteswap_ushort", cdecl, header: "<intrin.h>".}
  proc swapBytesBuiltin(a: uint32): uint32 {.
      importc: "_byteswap_ulong", cdecl, header: "<intrin.h>".}
  proc swapBytesBuiltin(a: uint64): uint64 {.
      importc: "_byteswap_uint64", cdecl, header: "<intrin.h>".}

template leSwap32*(a: uint32): uint32 =
  when system.cpuEndian == bigEndian:
    (a)
  else:
    swapBytesBuiltin(a)

template leSwap64*(a: uint64): uint64 =
  when system.cpuEndian == bigEndian:
    (a)
  else:
    swapBytesBuiltin(a)

template beSwap32*(a: uint32): uint32 =
  when system.cpuEndian == bigEndian:
    swapBytesBuiltin(a)
  else:
    (a)

template beSwap64*(a: uint64): uint64 =
  when system.cpuEndian == bigEndian:
    swapBytesBuiltin(a)
  else:
    (a)

template beLoad32*[T: byte|char](src: openarray[T], srco: int): uint32 =
  when nimvm:
    (uint32(src[srco + 0]) shl 24) or (uint32(src[srco + 1]) shl 16) or
      (uint32(src[srco + 2]) shl 8) or uint32(src[srco + 3])
  else:
    let p = cast[ptr uint32](unsafeAddr src[srco])[]
    leSwap32(p)

template leLoad32*[T: byte|char](src: openarray[T], srco: int): uint32 =
  when nimvm:
    (uint32(src[srco + 3]) shl 24) or (uint32(src[srco + 2]) shl 16) or
      (uint32(src[srco + 1]) shl 8) or uint32(src[srco + 0])
  else:
    let p = cast[ptr uint32](unsafeAddr src[srco])[]
    beSwap32(p)

template beLoad64*[T: byte|char](src: openarray[T], srco: int): uint64 =
  when nimvm:
    (uint64(src[srco + 0]) shl 56) or (uint64(src[srco + 1]) shl 48) or
      (uint64(src[srco + 2]) shl 40) or (uint64(src[srco + 3]) shl 32) or
      (uint64(src[srco + 4]) shl 24) or (uint64(src[srco + 5]) shl 16) or
      (uint64(src[srco + 6]) shl 8) or uint64(src[srco + 7])
  else:
    let p = cast[ptr uint64](unsafeAddr src[srco])[]
    leSwap64(p)

template leLoad64*[T: byte|char](src: openarray[T], srco: int): uint64 =
  when nimvm:
    (uint64(src[srco + 7]) shl 56) or (uint64(src[srco + 6]) shl 48) or
      (uint64(src[srco + 5]) shl 40) or (uint64(src[srco + 4]) shl 32) or
      (uint64(src[srco + 3]) shl 24) or (uint64(src[srco + 2]) shl 16) or
      (uint64(src[srco + 1]) shl 8) or uint64(src[srco + 0])
  else:
    let p = cast[ptr uint64](unsafeAddr src[srco])[]
    beSwap64(p)

template beStore32*(dst: var openarray[byte], so: int, v: uint32) =
  when nimvm:
    dst[so + 0] = byte((v shr 24) and 0xFF'u32)
    dst[so + 1] = byte((v shr 16) and 0xFF'u32)
    dst[so + 2] = byte((v shr 8) and 0xFF'u32)
    dst[so + 3] = byte(v and 0xFF'u32)
  else:
    cast[ptr uint32](addr dst[so])[] = leSwap32(v)

template beStore64*(dst: var openarray[byte], so: int, v: uint64) =
  when nimvm:
    dst[so + 0] = byte((v shr 56) and 0xFF'u64)
    dst[so + 1] = byte((v shr 48) and 0xFF'u64)
    dst[so + 2] = byte((v shr 40) and 0xFF'u64)
    dst[so + 3] = byte((v shr 32) and 0xFF'u64)
    dst[so + 4] = byte((v shr 24) and 0xFF'u64)
    dst[so + 5] = byte((v shr 16) and 0xFF'u64)
    dst[so + 6] = byte((v shr 8) and 0xFF'u64)
    dst[so + 7] = byte(v and 0xFF'u64)
  else:
    cast[ptr uint64](addr dst[so])[] = leSwap64(v)

template leStore32*(dst: var openarray[byte], so: int, v: uint32) =
  when nimvm:
    dst[so + 0] = byte(v and 0xFF'u32)
    dst[so + 1] = byte((v shr 8) and 0xFF'u32)
    dst[so + 2] = byte((v shr 16) and 0xFF'u32)
    dst[so + 3] = byte((v shr 24) and 0xFF'u32)
  else:
    cast[ptr uint32](addr dst[so])[] = beSwap32(v)

template leStore64*(dst: var openarray[byte], so: int, v: uint64) =
  when nimvm:
    dst[so + 0] = byte(v and 0xFF'u64)
    dst[so + 1] = byte((v shr 8) and 0xFF'u64)
    dst[so + 2] = byte((v shr 16) and 0xFF'u64)
    dst[so + 3] = byte((v shr 24) and 0xFF'u64)
    dst[so + 4] = byte((v shr 32) and 0xFF'u64)
    dst[so + 5] = byte((v shr 40) and 0xFF'u64)
    dst[so + 6] = byte((v shr 48) and 0xFF'u64)
    dst[so + 7] = byte((v shr 56) and 0xFF'u64)
  else:
    cast[ptr uint64](addr dst[so])[] = beSwap64(v)

template copyMem*[A, B](dst: var openarray[A], dsto: int,
                        src: openarray[B], srco: int,
                        length: int) =
  when nimvm:
    for i in 0 ..< length:
      dst[dsto + i] = A(src[srco + i])
  else:
    copyMem(addr dst[dsto], unsafeAddr src[srco], length * sizeof(B))
