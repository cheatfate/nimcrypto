#
#
#                    NimCrypto
#        (c) Copyright 2016-2018 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This is example of usage ``GCM[T]`` encryption/decryption.
## 
## In this sample we are using GCM[AES256], but you can use any block
## cipher from nimcrypto library.
import nimcrypto

var aliceKey = "Alice Key"
var aliceAad = "Alice Authentication Data"
var aliceData = "Alice hidden secret"
var aliceIv = "0123456789ABCDEF"

block:
  ## Nim's way API using openArray[byte].

  var ectx, dctx: GCM[aes256]
  var key: array[aes256.sizeKey, byte]
  var iv: array[aes256.sizeBlock, byte]
  var plainText = newSeq[byte](len(aliceData))
  var encText = newSeq[byte](len(aliceData))
  var decText = newSeq[byte](len(aliceData))
  var aadText = newSeq[byte](len(aliceAad))
  # Authentication tags
  var etag, dtag: array[aes256.sizeBlock, byte]

  # We do not need to pad data, `GCM` mode works byte by byte.
  copyMem(addr plainText[0], addr aliceData[0], len(aliceData))

  # We don not need to pad AAD data too.
  copyMem(addr aadText[0], addr aliceAad[0], len(aliceAad))

  # AES256 key size is 256 bits or 32 bytes, so we need to pad key with
  # 0 bytes.
  # WARNING! Do not use 0 byte padding in applications, this is done
  # as example.
  copyMem(addr key[0], addr aliceKey[0], len(aliceKey))

  # Initial vector IV size for GCM[aes256] is equal to AES256 block size 128
  # bits or 16 bytes.
  copyMem(addr iv[0], addr aliceIv[0], len(aliceIv))

  # Initialization of GCM[aes256] context with encryption key.
  ectx.init(key, iv, aadText)
  # Encryption process
  # In `GCM` mode there no need to pad plain data.
  ectx.encrypt(plainText, encText)
  # Obtain authentication tag.
  ectx.getTag(etag)
  # Clear context of CTR[aes256].
  ectx.clear()

  # Initialization of GCM[aes256] context with encryption key.
  dctx.init(key, iv, aadText)
  # Decryption process
  # In `GCM` mode there no need to pad encrypted data.
  dctx.decrypt(encText, decText)
  # Obtain authentication tag.
  dctx.getTag(dtag)
  # Clear context of CTR[aes256].
  dctx.clear()

  echo "IV: ", toHex(iv)
  echo "AAD: ", toHex(aadText)
  echo "PLAIN TEXT: ", toHex(plainText)
  echo "ENCODED TEXT: ", toHex(encText)
  echo "DECODED TEXT: ", toHex(decText)
  echo "ENCODED TAG: ", toHex(etag)
  echo "DECODED TAG: ", toHex(dtag)

  # Note that if tags are not equal, decrypted data must not be considered as
  # successfully decrypted.
  assert(equalMem(addr dtag[0], addr etag[0], len(etag)))
  # Compare plaintext with decoded text.
  assert(equalMem(addr plainText[0], addr decText[0], len(plainText)))

