mode = ScriptMode.Verbose

packageName   = "nimcrypto"
version       = "0.1.0"
author        = "Eugene Kabanov"
description   = "Nim cryptographic library"
license       = "MIT"
skipDirs      = @["tests", "Nim"]

requires "nim >= 0.18.0"

task tests, "Runs the test suite":
  exec "nim c -r tests/testkeccak"
  exec "nim c -r tests/testsha2"
  exec "nim c -r tests/testripemd"
  exec "nim c -r tests/testhmac"
  exec "nim c -r tests/testrijndael"
  exec "nim c -r tests/testtwofish"
  exec "nim c -r tests/testblowfish"
  exec "nim c -r tests/testbcmode"
