mode = ScriptMode.Verbose

packageName   = "nimcrypto"
version       = "0.3.0"
author        = "Eugene Kabanov"
description   = "Nim cryptographic library"
license       = "MIT"
skipDirs      = @["tests", "Nim"]

requires "nim > 0.18.0"

task tests, "Runs the test suite":
  exec "nim c -r tests/testkeccak"
  exec "nim c -r tests/testsha2"
  exec "nim c -r tests/testripemd"
  exec "nim c -r tests/testhmac"
  exec "nim c -r tests/testrijndael"
  exec "nim c -r tests/testtwofish"
  exec "nim c -r tests/testblowfish"
  exec "nim c -r tests/testbcmode"
  exec "nim c -r tests/testsysrand"
  exec "nim c -r tests/testkdf"

  exec "nim c -d:release -r tests/testkeccak"
  exec "nim c -d:release -r tests/testsha2"
  exec "nim c -d:release -r tests/testripemd"
  exec "nim c -d:release -r tests/testhmac"
  exec "nim c -d:release -r tests/testrijndael"
  exec "nim c -d:release -r tests/testtwofish"
  exec "nim c -d:release -r tests/testblowfish"
  exec "nim c -d:release -r tests/testbcmode"
  exec "nim c -d:release -r tests/testsysrand"
  exec "nim c -d:release -r tests/testkdf"
