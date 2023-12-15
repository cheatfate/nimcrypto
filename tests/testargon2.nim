import nimcrypto/argon2, nimcrypto/utils
import unittest

## Tests made according to official test vectors
## [https://www.rfc-editor.org/rfc/rfc9106.txt].

when defined(nimHasUsed): {.used.}

proc test1(argonType: Argon2Type, threadsCount: int): seq[byte] =
  const
    password = utils.fromHex(
      "0101010101010101010101010101010101010101010101010101010101010101")
    salt = utils.fromHex(
      "02020202020202020202020202020202")
    secret = utils.fromHex(
      "0303030303030303")
    ad = utils.fromHex(
      "040404040404040404040404")
  var output: array[32, byte]
  let length = argon2(argonType, password, salt, ad, secret, output,
                      3'u32, 4'u32, 32'u32, uint32(threadsCount))
  var res = @output
  res.setLen(length)
  res

proc test2(argonType: Argon2Type, threadsCount: int): seq[byte] =
  const
    password = utils.fromHex(
      "0101010101010101010101010101010101010101010101010101010101010101")
    salt = utils.fromHex(
      "02020202020202020202020202020202")
    secret = utils.fromHex(
      "0303030303030303")
    ad = utils.fromHex(
      "040404040404040404040404")
  let output = argon2(argonType, password, salt, ad, secret, 32,
                      3'u32, 4'u32, 32'u32, uint32(threadsCount))
  var res = @output
  res

suite "ARGON2 Tests":
  test "Argon2id singlethreaded test vector":
    check:
      test1(Argon2Type.TypeID, 1) ==
        utils.fromHex(
          "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
      test2(Argon2Type.TypeID, 1) ==
        utils.fromHex(
          "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
  test "Argon2d singlethreaded test vector":
    check:
      test1(Argon2Type.TypeD, 1) ==
        utils.fromHex(
          "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb")
      test2(Argon2Type.TypeD, 1) ==
        utils.fromHex(
          "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb")
  test "Argon2i singlethreaded test vector":
    check:
      test1(Argon2Type.TypeI, 1) ==
        utils.fromHex(
          "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8")
      test2(Argon2Type.TypeI, 1) ==
        utils.fromHex(
          "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8")
  test "Argon2id multithreaded test vector":
    when compileOption("threads"):
      check:
        test1(Argon2Type.TypeID, 4) ==
          utils.fromHex(
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        test2(Argon2Type.TypeID, 4) ==
          utils.fromHex(
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    else:
      skip()
  test "Argon2d multithreaded test vector":
    when compileOption("threads"):
      check:
        test1(Argon2Type.TypeD, 4) ==
          utils.fromHex(
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb")
        test2(Argon2Type.TypeD, 4) ==
          utils.fromHex(
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb")
    else:
      skip()
  test "Argon2i multithreaded test vector":
    when compileOption("threads"):
      check:
        test1(Argon2Type.TypeI, 4) ==
          utils.fromHex(
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8")
        test2(Argon2Type.TypeI, 4) ==
          utils.fromHex(
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8")
    else:
      skip()
