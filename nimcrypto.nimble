# Package

version       = "0.3.8"
author        = "Eugene Kabanov"
description   = "Nim cryptographic library"
license       = "MIT"
skipDirs      = @["tests", "examples", "Nim", "docs"]

# Dependencies

requires "nim > 0.18.0"

# Tests

task tests, "Runs the test suite":
  for tfile in @[
      "testkeccak",
      "testsha2",
      "testripemd",
      "testblake2",
      "testhmac",
      "testrijndael",
      "testtwofish",
      "testblowfish",
      "testbcmode",
      "testsysrand",
      "testkdf",
      "testapi",
    ]:
    for cmd in @[
        "nim c -f -r tests/" & tfile,
        "nim c -f -d:release -r tests/" & tfile,
        "nim c -f -d:release --threads:on -r tests/" & tfile,
      ]:
      echo "\n" & cmd
      exec cmd
      rmFile("tests/" & tfile.toExe())

  for efile in @[
      "ecb",
      "cbc",
      "ofb",
      "cfb",
      "ctr",
      "gcm",
    ]:
    for cmd in @[
        "nim c -f -r examples/" & efile,
        "nim c -f -r --threads:on examples/" & efile,
      ]:
      echo "\n" & cmd
      exec cmd
      rmFile("examples/" & efile.toExe())

