import nimcrypto/sysrand, nimcrypto/utils
import unittest

when defined(nimHasUsed): {.used.}

suite "OS random source Tests":
  test "Availability test":
    var buffer: array[1024, uint8]
    let count = randomBytes(addr buffer[0], 1024)
    check:
      count == 1024
      buffer.isFullZero() == false
  test "OpenArray[T] test":
    var buffer1: array[256, uint8]
    var buffer2: array[128, uint16]
    var buffer4: array[64, uint32]
    var buffer8: array[32, uint64]
    let count1 = randomBytes(buffer1)
    let count2 = randomBytes(buffer2)
    let count4 = randomBytes(buffer4)
    let count8 = randomBytes(buffer8)
    check:
      count1 == 256
      count2 == 128
      count4 == 64
      count8 == 32
      buffer1.isFullZero() == false
      buffer2.isFullZero() == false
      buffer4.isFullZero() == false
      buffer8.isFullZero() == false
      equalMem(addr buffer1[0], addr buffer2[0], 256) != true
      equalMem(addr buffer1[0], addr buffer4[0], 256) != true
      equalMem(addr buffer1[0], addr buffer8[0], 256) != true
      equalMem(addr buffer2[0], addr buffer4[0], 256) != true
      equalMem(addr buffer2[0], addr buffer8[0], 256) != true
      equalMem(addr buffer4[0], addr buffer8[0], 256) != true
  test "Issue #33 test":
    proc test(): bool {.raises:[].} =
      var test: array[8, byte]
      if randomBytes(test) == 8:
        result = true

    check test() == true

  test "getrandom partial-read offset test":
    # A source such as getrandom(2) may return fewer bytes than requested for
    # large buffers. `fillRandomBytes` must resume at the correct offset after
    # each short read; otherwise later reads overwrite the beginning of the
    # buffer and leave the tail untouched while still reporting full success.
    const Total = 64
    var buffer: array[Total, byte]

    proc shortReader(pbytes: pointer, nbytes: int): int {.gcsafe, raises: [].} =
      # Emulate a source that only ever produces up to 8 bytes per call, writing
      # a non-zero marker so an untouched tail is detectable.
      let chunk = min(nbytes, 8)
      let arr = cast[ptr UncheckedArray[byte]](pbytes)
      for i in 0 ..< chunk:
        arr[i] = 0xAA'u8
      chunk

    let filled = fillRandomBytes(addr buffer[0], Total, shortReader)

    var allWritten = true
    for b in buffer:
      if b != 0xAA'u8:
        allWritten = false

    check:
      filled == Total
      allWritten == true
