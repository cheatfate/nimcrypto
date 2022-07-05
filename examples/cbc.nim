#
#
#                    NimCrypto
#        (c) Copyright 2016-2018 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This is example of usage ``CBC[T]`` encryption/decryption.
## 
## In this sample we are using CBC[AES256], but you can use any block
## cipher from nimcrypto library.
import nimcrypto

var aliceKey = "Alice Key"
var aliceData = "Alice hidden secret"
var aliceIv = "0123456789ABCDEF"

block:
  ## Nim's way API using openArray[byte].

  var ectx, dctx: CBC[aes256]
  var key: array[aes256.sizeKey, byte]
  var iv: array[aes256.sizeBlock, byte]
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

  # Initial vector IV size for CBC[aes256] is equal to AES256 block size 128
  # bits or 16 bytes.
  copyMem(addr iv[0], addr aliceIv[0], len(aliceIv))

  # Initialization of CBC[aes256] context with encryption key
  ectx.init(key, iv)
  # Encryption process
  ectx.encrypt(plainText, encText)
  # Clear context of CBC[aes256]
  ectx.clear()

  # Initialization of CBC[aes256] context with encryption key
  dctx.init(key, iv)
  # Decryption process
  dctx.decrypt(encText, decText)
  # Clear context of CBC[aes256]
  dctx.clear()

  echo "IV: ", toHex(iv)
  echo "PLAIN TEXT: ", toHex(plainText)
  echo "ENCODED TEXT: ", toHex(encText)
  echo "DECODED TEXT: ", toHex(decText)

  assert(equalMem(addr plainText[0], addr decText[0], len(plainText)))

block:
  ## UNSAFE way API pointer/size.

  var ectx, dctx: CBC[aes256]
  var key: array[aes256.sizeKey, byte]
  var iv: array[aes256.sizeBlock, byte]
  var plainText: array[aes256.sizeBlock * 2, byte]
  var encText: array[aes256.sizeBlock * 2, byte]
  var decText: array[aes256.sizeBlock * 2, byte]

  var ptrKey = cast[ptr byte](addr key[0])
  var ptrPlainText = cast[ptr byte](addr plainText[0])
  var ptrEncText = cast[ptr byte](addr encText[0])
  var ptrDecText = cast[ptr byte](addr decText[0])
  var ptrIv = cast[ptr byte](addr iv[0])
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

  # Initial vector IV size for CBC[aes256] is equal to AES256 block size 128
  # bits or 16 bytes.
  copyMem(addr iv[0], addr aliceIv[0], len(aliceIv))

  # Initialization of CBC[aes256] context with encryption key
  ectx.init(ptrKey, ptrIv)
  # Encryption process
  ectx.encrypt(ptrPlainText, ptrEncText, dataLen)
  # Clear context of CBC[aes256]
  ectx.clear()

  # Initialization of CBC[aes256] context with encryption key
  dctx.init(ptrKey, ptrIv)
  # Decryption process
  dctx.decrypt(ptrEncText, ptrDecText, dataLen)
  # Clear context of CBC[aes256]
  dctx.clear()

  echo "IV: ", toHex(iv)
  echo "PLAIN TEXT: ", toHex(plainText)
  echo "ENCODED TEXT: ", toHex(encText)
  echo "DECODED TEXT: ", toHex(decText)

  assert(equalMem(addr plainText[0], addr decText[0], len(plainText)))

block:
  ## Nim's way API using strings.
  var ectx, dctx: CBC[aes256]
  var key = newString(aes256.sizeKey)
  var iv = newString(aes256.sizeBlock)
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

  # Initial vector IV size for CBC[aes256] is equal to AES256 block size 128
  # bits or 16 bytes.
  copyMem(addr iv[0], addr aliceIv[0], len(aliceIv))

  # Initialization of CBC[aes256] context with encryption key
  ectx.init(key, iv)
  # Encryption process
  ectx.encrypt(plainText, encText)
  # Clear context of CBC[aes256]
  ectx.clear()

  # Initialization of CBC[aes256] context with encryption key
  dctx.init(key, iv)
  # Decryption process
  dctx.decrypt(encText, decText)
  # Clear context of CBC[aes256]
  dctx.clear()

  echo "IV: ", $iv
  echo "PLAIN TEXT: ", $plainText
  echo "ENCODED TEXT: ", $encText
  echo "DECODED TEXT: ", $decText

  assert(equalMem(addr plainText[0], addr decText[0], len(plainText)))
