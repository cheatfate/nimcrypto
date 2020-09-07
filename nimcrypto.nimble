# Package

version       = "0.5.4"
author        = "Eugene Kabanov"
description   = "Nim cryptographic library"
license       = "MIT"
skipDirs      = @["tests", "examples", "Nim", "docs"]

# Dependencies

requires "nim > 0.18.0"

# Tests

task test, "Runs the test suite":
  let testCommands = @[
    "nim c -f -r tests/",
    "nim c -f -d:danger -r tests/",
    "nim c -f -d:danger --threads:on -r tests/",
  ]
  let exampleFiles = @[
    "ecb", "cbc", "ofb", "cfb", "ctr", "gcm"
  ]
  let exampleCommands = @[
      "nim c -f -r --threads:on examples/",
  ]

  for cmd in testCommands:
    echo "\n" & cmd & "testall"
    exec cmd & "testall"
    rmFile("tests/testall".toExe())

  for efile in exampleFiles:
    for cmd in exampleCommands:
      echo "\n" & cmd & efile
      exec cmd & efile
      rmFile("examples/" & efile.toExe())

  exec("nim c -f -r -d:nimcryptoLowercase tests/testapi")
  exec("nim c -f -r -d:nimcrypto0xPrefix tests/testapi")
  exec("nim c -f -r -d:nimcrypto0xPrefix -d:nimcryptoLowercase tests/testapi")
