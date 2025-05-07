import nimcrypto/scrypt
import unittest

when defined(nimHasUsed): {.used.}

suite "Issues test":
  test "Issue #85 test":
    func doScrypt(key, salt: string, N, r, p, length: int): seq[byte] =
      let (xyvLen, bLen) = scryptCalc(N, r, p)
      var xyv = newSeq[uint32](xyvLen)
      var b = newSeq[byte](bLen)
      result = newSeq[byte](length)

      if scrypt(key, salt, N, r, p, xyv, b, result) != length:
        raise ValueError.newException("Error: scrypt failed")

    discard doScrypt("a", "b", N = 16384, r = 8, p = 1, length = 64)
