# Package

version       = "0.6.0"
author        = "Eugene Kabanov"
description   = "Nim cryptographic library"
license       = "MIT"
skipDirs      = @["tests", "examples", "Nim", "docs"]

# Dependencies

requires "nim >= 1.6"

# Tests

let
  nimc = getEnv("NIMC", "nim") # Which nim compiler to use
  mmopt =
    when (NimMajor, NimMinor) >= (2, 0):
      "--mm:orc"
    else:
      "--gc:orc"

task test, "Runs the test suite":
  var testCommands = @[
    nimc & " c -f -r tests/",
    nimc & " c -f -d:danger -r tests/",
    nimc & " c -f -d:danger --threads:on -r tests/",
    nimc & " c -f --passC=\"-fsanitize=undefined -fsanitize-undefined-trap-on-error\" --passL:\"-fsanitize=undefined -fsanitize-undefined-trap-on-error\" -r tests/",
    nimc & " c -f " & mmopt & " --threads:on -r tests/"
  ]

  let exampleFiles = @[
    "ecb", "cbc", "ofb", "cfb", "ctr", "gcm"
  ]
  var exampleCommands = @[
      nimc & " c -f -r --threads:on examples/",
      nimc & " c -f " & mmopt & " --threads:on -r examples/"
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

  exec(nimc & " c -f -r -d:nimcryptoLowercase tests/testapi")
  exec(nimc & " c -f -r -d:nimcrypto0xPrefix tests/testapi")
  exec(nimc & " c -f -r -d:nimcrypto0xPrefix -d:nimcryptoLowercase tests/testapi")
