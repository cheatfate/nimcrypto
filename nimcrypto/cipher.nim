#
#
#                    NimCrypto
#        (c) Copyright 2016 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements abstract object for all block ciphers.

type
  CipherContext* = ref object of RootRef
    sizeBlock*: int
    sizeKey*: int
