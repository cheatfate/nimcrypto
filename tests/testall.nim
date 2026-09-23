import testsysrand
import testsha1, testkeccak, testripemd, testblake2
import testhmac, testkdf, testscrypt
import testrijndael, testblowfish, testtwofish
import testbcmode
import testapi, testutils, testissues


when (NimMajor, NimMinor, NimPatch) >= (2, 2, 8):
  # https://github.com/cheatfate/nimcrypto/issues/98
  import testsha2
