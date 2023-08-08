import nimcrypto/utils
import unittest

when defined(nimHasUsed): {.used.}

suite "Utilities test":
  test "Can parse hex string with prefix":
    let a = "0x1234"
    let b = fromHex(a)
    check: b == @[byte 0x12, 0x34]

  test "Memory alignment undefined behavior test":
    var x = [0x01'u8, 0x02'u8, 0x03'u8, 0x04'u8, 0x05'u8, 0x06'u8, 0x07'u8,
             0x08'u8, 0x09'u8]
    var y: array[9, byte]

    let a = beLoad32(x, 1)
    let b = leLoad32(x, 1)
    let c = beLoad64(x, 1)
    let d = leLoad64(x, 1)
    beStore32(y, 1, a)
    check y[1 .. 4] == x[1 .. 4]
    leStore32(y, 1, b)
    check y[1 .. 4] == x[1 .. 4]
    beStore64(y, 1, c)
    check y[1 .. 8] == x[1 .. 8]
    leStore64(y, 1, d)
    check y[1 .. 8] == x[1 .. 8]
