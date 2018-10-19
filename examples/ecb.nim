#
#
#                    NimCrypto
#        (c) Copyright 2016-2018 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This is example of usage ``ECB[T]`` encryption/decryption.
import nimcrypto

var aliceKey = "Alice Key"
var aliceData = "Alice hidden secret"

block:
  ## Nim's way API using openarray[byte].

  var ectx, dctx: ECB[aes256]
  var key: array[aes256.sizeKey, byte]
  var plainText: array[aes256.sizeBlock * 2, byte]
  var encText: array[aes256.sizeBlock * 2, byte]
  var decText: array[aes256.sizeBlock * 2, byte]

  # AES256 block size is 128 bits or 16 bytes, so we need to pad plaintext with
  # 0 bytes.
  # WARNING! Do not use 0 byte padding in applications, this is done
  # as example.
  copyMem(addr plainText[0], addr aliceData[0], len(aliceData))

  # AES256 key size is 256 bits or 32 bytes, so we need to pad key with
  # 0 bytes.
  # WARNING! Do not use 0 byte padding in applications, this is done
  # as example.
  copyMem(addr key[0], addr aliceKey[0], len(aliceKey))

  # Initialization of ECB[aes256] context with encryption key
  ectx.init(key)
  # Encryption process
  ectx.encrypt(plainText, encText)
  # Clear context of ECB[aes256]
  ectx.clear()

  # Initialization of ECB[aes256] context with encryption key
  dctx.init(key)
  # Decryption process
  dctx.decrypt(encText, decText)
  # Clear context of ECB[aes256]
  dctx.clear()

  echo "PLAIN TEXT: ", toHex(plainText)
  echo "ENCODED TEXT: ", toHex(encText)
  echo "DECODED TEXT: ", toHex(decText)

  assert(equalMem(addr plainText[0], addr decText[0], len(plainText)))

block:
  ## UNSAFE way API pointer/size.

  var ectx, dctx: ECB[aes256]
  var key: array[aes256.sizeKey, byte]
  var plainText: array[aes256.sizeBlock * 2, byte]
  var encText: array[aes256.sizeBlock * 2, byte]
  var decText: array[aes256.sizeBlock * 2, byte]

  var ptrKey = cast[ptr byte](addr key[0])
  var ptrPlainText = cast[ptr byte](addr plainText[0])
  var ptrEncText = cast[ptr byte](addr encText[0])
  var ptrDecText = cast[ptr byte](addr decText[0])
  let dataLen = uint(len(plainText))

  # AES256 block size is 128 bits or 16 bytes, so we need to pad plaintext with
  # 0 bytes.
  # WARNING! Do not use 0 byte padding in applications, this is done
  # as example.
  copyMem(addr plainText[0], addr aliceData[0], len(aliceData))

  # AES256 key size is 256 bits or 32 bytes, so we need to pad key with
  # 0 bytes.
  # WARNING! Do not use 0 byte padding in applications, this is done
  # as example.
  copyMem(addr key[0], addr aliceKey[0], len(aliceKey))

  # Initialization of ECB[aes256] context with encryption key
  ectx.init(ptrKey)
  # Encryption process
  ectx.encrypt(ptrPlainText, ptrEncText, dataLen)
  # Clear context of ECB[aes256]
  ectx.clear()

  # Initialization of ECB[aes256] context with encryption key
  dctx.init(ptrKey)
  # Decryption process
  dctx.decrypt(ptrEncText, ptrDecText, dataLen)
  # Clear context of ECB[aes256]
  dctx.clear()

  echo "PLAIN TEXT: ", toHex(plainText)
  echo "ENCODED TEXT: ", toHex(encText)
  echo "DECODED TEXT: ", toHex(decText)

  assert(equalMem(addr plainText[0], addr decText[0], len(plainText)))

block:
  ## Nim's way API using strings.
  var ectx, dctx: ECB[aes256]
  var key = newString(aes256.sizeKey)
  var plainText = newString(aes256.sizeBlock * 2)
  var encText = newString(aes256.sizeBlock * 2)
  var decText = newString(aes256.sizeBlock * 2)

  # AES256 block size is 128 bits or 16 bytes, so we need to pad plaintext with
  # 0 bytes.
  # WARNING! Do not use 0 byte padding in applications, this is done
  # as example.
  copyMem(addr plainText[0], addr aliceData[0], len(aliceData))

  # AES256 key size is 256 bits or 32 bytes, so we need to pad key with
  # 0 bytes.
  # WARNING! Do not use 0 byte padding in applications, this is done
  # as example.
  copyMem(addr key[0], addr aliceKey[0], len(aliceKey))

  # Initialization of ECB[aes256] context with encryption key
  ectx.init(key)
  # Encryption process
  ectx.encrypt(plainText, encText)
  # Clear context of ECB[aes256]
  ectx.clear()

  # Initialization of ECB[aes256] context with encryption key
  dctx.init(key)
  # Decryption process
  dctx.decrypt(encText, decText)
  # Clear context of ECB[aes256]
  dctx.clear()

  echo "PLAIN TEXT: ", $plainText
  echo "ENCODED TEXT: ", $encText
  echo "DECODED TEXT: ", $decText

  assert(equalMem(addr plainText[0], addr decText[0], len(plainText)))
