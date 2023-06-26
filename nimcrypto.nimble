# Package

version       = "0.5.4"
author        = "Eugene Kabanov"
description   = "Nim cryptographic library"
license       = "MIT"
skipDirs      = @["tests", "examples", "Nim", "docs"]

# Dependencies

requires "nim > 0.18.0"

# Tests

let nimc = getEnv("NIMC", "nim") # Which nim compiler to use

task test, "Runs the test suite":
  var testCommands = @[
    nimc & " c -f -r tests/",
    nimc & " c -f -d:danger -r tests/",
    nimc & " c -f -d:danger --threads:on -r tests/",
  ]

  when (NimMajor, NimMinor) >= (1, 5):
    testCommands.add(nimc & " c -f --gc:orc --threads:on -r tests/")

  let exampleFiles = @[
    "ecb", "cbc", "ofb", "cfb", "ctr", "gcm"
  ]
  var exampleCommands = @[
      nimc & " c -f -r --threads:on examples/",
  ]

  when (NimMajor, NimMinor) >= (1, 5):
    exampleCommands.add "nim c -f --gc:orc --threads:on -r examples/"

  for cmd in testCommands:
    echo "\n" & cmd & "testall"
    exec cmd & "testall"
    rmFile("tests/testall".toExe())

  for efile in exampleFiles:
    for cmd in exampleCommands:
      echo "\n" & cmd & efile
      exec cmd & efile
      rmFile("examples/" & efile.toExe())

  exec(nimc & " c -f -r -d:nimcryptoLowercase tests/testapi")
  exec(nimc & " c -f -r -d:nimcrypto0xPrefix tests/testapi")
  exec(nimc & " c -f -r -d:nimcrypto0xPrefix -d:nimcryptoLowercase tests/testapi")
