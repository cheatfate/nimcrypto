import nimcrypto/sysrand
import unittest

suite "OS random source Tests":
  test "Availability test":
    var buffer: array[1024, uint8]
    let count = randomBytes(addr buffer[0], 1024)
    check(count == 1024)
