import nimcrypto/utils
import unittest

when defined(nimHasUsed): {.used.}

suite "Utilities test":
  test "Can parse hex string with prefix":
    let a = "0x1234"
    let b = fromHex(a)
    check: b == @[byte 0x12, 0x34]