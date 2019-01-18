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
  let testFiles = @[
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
    ]
  let testCommands = @[
      "nim c -f -r tests/",
      "nim c -f -d:release -r tests/",
      "nim c -f -d:release --threads:on -r tests/",
    ]
  let exampleFiles = @[
      "ecb",
      "cbc",
      "ofb",
      "cfb",
      "ctr",
      "gcm",
    ]
  let exampleCommands = @[
      "nim c -f -r examples/",
      "nim c -f -r --threads:on examples/",
    ]

  for tfile in testFiles:
    for cmd in testCommands:
      echo "\n" & cmd & tfile
      exec cmd & tfile
      rmFile("tests/" & tfile.toExe())
  for efile in exampleFiles:
    for cmd in exampleCommands:
      echo "\n" & cmd & efile
      exec cmd & efile
      rmFile("examples/" & efile.toExe())

