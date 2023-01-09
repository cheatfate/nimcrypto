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
##
## Constant-time hexadecimal processing is Nim's adaptation of `src/hex.c` from
## decent library "Constant-Time Toolkit" (https://github.com/pornin/CTTK)
## Copyright (c) 2018 Thomas Pornin <pornin@bolet.org>

{.deadCodeElim:on.}

type
  HexFlags* {.pure.} = enum
    LowerCase,  ## Produce lowercase hexadecimal characters
    PadOdd,     ## Pads odd strings
    SkipSpaces, ## Skips all the whitespace characters inside of string
    SkipPrefix  ## Skips `0x` and `x` prefixes at the begining of string

template ROL*(x: uint32, n: int): uint32 =
  (x shl uint32(n and 0x1F)) or (x shr uint32(32 - (n and 0x1F)))

template ROL*(x: uint64, n: int): uint64 =
  (x shl uint64(n and 0x3F)) or (x shr uint64(64 - (n and 0x3F)))

template ROR*(x: uint32, n: int): uint32 =
  (x shr uint32(n and 0x1F)) or (x shl uint32(32 - (n and 0x1F)))

template ROR*(x: uint64, n: int): uint64 =
  (x shr uint64(n and 0x3F)) or (x shl uint64(64 - (n and 0x3F)))

proc `-`(x: uint32): uint32 {.inline.} =
  result = (0xFFFF_FFFF'u32 - x) + 1'u32

proc LT(x, y: uint32): uint32 {.inline.} =
  let z = x - y
  (z xor ((y xor x) and (y xor z))) shr 31

proc hexValue(c: char): int =
  let x = uint32(c) - 0x30'u32
  let y = uint32(c) - 0x41'u32
  let z = uint32(c) - 0x61'u32
  let r = ((x + 1'u32) and -LT(x, 10)) or
          ((y + 11'u32) and -LT(y, 6)) or
          ((z + 11'u32) and -LT(z, 6))
  int(r) - 1

proc hexDigit(x: int, lowercase: bool = false): char =
  var off = uint32(0x41 - 0x3A)
  if lowercase:
    off += 0x20
  char(0x30'u32 + uint32(x) + (off and not((uint32(x) - 10) shr 8)))

proc bytesToHex*(src: openArray[byte], dst: var openArray[char],
                 flags: set[HexFlags]): int =
  if len(dst) == 0:
    (len(src) shl 1)
  else:
    var halflast = false
    let dstlen = len(dst)
    var srclen = len(src)

    if dstlen < (srclen shl 1):
      if (dstlen and 1) == 1:
        srclen = (dstlen - 1) shr 1
        halflast = true
      else:
        srclen = (dstlen shr 1)

    let lowercase = (HexFlags.LowerCase in flags)

    var k = 0
    for i in 0 ..< srclen:
      let x = int(src[i])
      dst[k + 0] = hexDigit(x shr 4, lowercase)
      dst[k + 1] = hexDigit(x and 15, lowercase)
      inc(k, 2)

    if halflast:
      let x = int(src[srclen])
      dst[k + 0] = hexDigit(x shr 4, lowercase)
      inc(k)

    k

proc hexToBytes*(src: openArray[char], dst: var openArray[byte],
                 flags: set[HexFlags]): int =
  var halfbyte = false
  var acc: byte
  var v = 0
  let offset =
    if (HexFlags.SkipPrefix in flags):
      let srclen = len(src)
      if srclen > 1:
        if (src[0] == '0') and (src[1] in {'x', 'X'}):
          2
        elif src[0] in {'x', 'X'}:
          1
        else:
          0
      else:
        0
    else:
      0

  for i in offset ..< len(src):
    let c = byte(src[i])
    let d = hexValue(src[i])

    if d < 0:
      if (HexFlags.SkipSpaces in flags) and (c <= 0x20'u8):
        continue
      if (HexFlags.PadOdd in flags) and halfbyte:
        if v < len(dst):
          dst[v] = acc
        inc(v)
      return v

    if halfbyte:
      if v < len(dst):
        dst[v] = acc + byte(d)
      inc(v)
    else:
      if v == len(dst):
        return v
      acc = byte(d) shl 4

    halfbyte = not(halfbyte)

  if halfbyte:
    if (HexFlags.PadOdd in flags):
      if v < len(dst):
        dst[v] = acc
      inc(v)
    else:
      return v
  return v

proc toHex*(a: openArray[byte], flags: set[HexFlags]): string =
  var res = newString(len(a) shl 1)
  discard bytesToHex(a, res, flags)
  res

proc toHex*(a: openArray[byte], lowercase: bool = false): string {.inline.} =
  var res = newString(len(a) shl 1)
  if lowercase:
    discard bytesToHex(a, res, {HexFlags.LowerCase})
  else:
    discard bytesToHex(a, res, {})
  res

proc hexToBytes*(a: string, output: var openArray[byte]) {.inline.} =
  discard hexToBytes(a, output, {HexFlags.SkipPrefix, HexFlags.PadOdd})

proc fromHex*(a: string): seq[byte] =
  var buf = newSeq[byte](len(a) shr 1)
  let res = hexToBytes(a, buf, {HexFlags.SkipPrefix, HexFlags.PadOdd})
  buf.setLen(res)
  buf

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

proc burnArray*[T](a: var openArray[T]) {.inline.} =
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

proc isFullZero*[T](a: openArray[T]): bool {.inline.} =
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
    (uint64(pp[offset + 0]) shl 56) or (uint64(pp[offset + 1]) shl 48) or
      (uint64(pp[offset + 2]) shl 40) or (uint64(pp[offset + 3]) shl 32) or
      (uint64(pp[offset + 4]) shl 24) or (uint64(pp[offset + 5]) shl 16) or
      (uint64(pp[offset + 6]) shl 8) or uint64(pp[offset + 7])

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

template beLoad32*[T: byte|char](src: openArray[T], srco: int): uint32 =
  when nimvm:
    (uint32(src[srco + 0]) shl 24) or (uint32(src[srco + 1]) shl 16) or
      (uint32(src[srco + 2]) shl 8) or uint32(src[srco + 3])
  else:
    let p = cast[ptr uint32](unsafeAddr src[srco])[]
    leSwap32(p)

template leLoad32*[T: byte|char](src: openArray[T], srco: int): uint32 =
  when nimvm:
    (uint32(src[srco + 3]) shl 24) or (uint32(src[srco + 2]) shl 16) or
      (uint32(src[srco + 1]) shl 8) or uint32(src[srco + 0])
  else:
    let p = cast[ptr uint32](unsafeAddr src[srco])[]
    beSwap32(p)

template beLoad64*[T: byte|char](src: openArray[T], srco: int): uint64 =
  when nimvm:
    (uint64(src[srco + 0]) shl 56) or (uint64(src[srco + 1]) shl 48) or
      (uint64(src[srco + 2]) shl 40) or (uint64(src[srco + 3]) shl 32) or
      (uint64(src[srco + 4]) shl 24) or (uint64(src[srco + 5]) shl 16) or
      (uint64(src[srco + 6]) shl 8) or uint64(src[srco + 7])
  else:
    let p = cast[ptr uint64](unsafeAddr src[srco])[]
    leSwap64(p)

template leLoad64*[T: byte|char](src: openArray[T], srco: int): uint64 =
  when nimvm:
    (uint64(src[srco + 7]) shl 56) or (uint64(src[srco + 6]) shl 48) or
      (uint64(src[srco + 5]) shl 40) or (uint64(src[srco + 4]) shl 32) or
      (uint64(src[srco + 3]) shl 24) or (uint64(src[srco + 2]) shl 16) or
      (uint64(src[srco + 1]) shl 8) or uint64(src[srco + 0])
  else:
    let p = cast[ptr uint64](unsafeAddr src[srco])[]
    beSwap64(p)

template beStore32*(dst: var openArray[byte], so: int, v: uint32) =
  when nimvm:
    dst[so + 0] = byte((v shr 24) and 0xFF'u32)
    dst[so + 1] = byte((v shr 16) and 0xFF'u32)
    dst[so + 2] = byte((v shr 8) and 0xFF'u32)
    dst[so + 3] = byte(v and 0xFF'u32)
  else:
    cast[ptr uint32](addr dst[so])[] = leSwap32(v)

template beStore64*(dst: var openArray[byte], so: int, v: uint64) =
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

template leStore32*(dst: var openArray[byte], so: int, v: uint32) =
  when nimvm:
    dst[so + 0] = byte(v and 0xFF'u32)
    dst[so + 1] = byte((v shr 8) and 0xFF'u32)
    dst[so + 2] = byte((v shr 16) and 0xFF'u32)
    dst[so + 3] = byte((v shr 24) and 0xFF'u32)
  else:
    cast[ptr uint32](addr dst[so])[] = beSwap32(v)

template leStore64*(dst: var openArray[byte], so: int, v: uint64) =
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

template copyMem*[A, B](dst: var openArray[A], dsto: int,
                        src: openArray[B], srco: int,
                        length: int) =
  when nimvm:
    for i in 0 ..< length:
      dst[dsto + i] = A(src[srco + i])
  else:
    copyMem(addr dst[dsto], unsafeAddr src[srco], length * sizeof(B))
