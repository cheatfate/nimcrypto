#
#
#                    NimCrypto
#         (c) Copyright 2026 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

{.push raises: [].}
{.used.}

import ".."/hash
export hash

const
  KECCAK_AVX_compress* = true

func keccakCompress*(
    state: var openArray[byte],
    data: openArray[byte],
    rsize: int
) {.raises: [], gcsafe, nimcall.} =
  discard
