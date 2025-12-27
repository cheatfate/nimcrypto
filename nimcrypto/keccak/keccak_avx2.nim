when defined(amd64):
  {.passC:"-mavx2".}

  when defined(vcc):
    {.pragma: x86type, bycopy, header:"<intrin.h>".}
    {.pragma: x86proc, nodecl, header:"<intrin.h>".}
  else:
    {.pragma: x86type, bycopy, header:"<x86intrin.h>".}
    {.pragma: x86proc, nodecl, header:"<x86intrin.h>".}

  const
    KECCAK_AVX2_compress* = true
    Rho8 = [0x0605040302010007'u64, 0x0E0D0C0B0A09080F'u64,
            0x1615141312111017'u64, 0x1E1D1C1B1A19181F'u64]
    Rho56 = [0x0007060504030201'u64, 0x080F0E0D0C0B0A09'u64,
             0x1017161514131211'u64, 0x181F1E1D1C1B1A19'u64]

  type
    m256i* {.importc: "__m256i", x86type.} = object
      data: array[4, uint64]
    m128i* {.importc: "__m128i", x86type.} = object
      data: array[2, uint64]

  func mm256_andnot_si256(a, b: m256i): m256i {.
       importc: "_mm256_andnot_si256", x86proc.}
  func mm256_load_si256(a: ptr m256i): m256i {.
       importc: "_mm256_load_si256", x86proc.}
  func mm256_loadu_si256(a: ptr m256i): m256i {.
       importc: "_mm256_loadu_si256", x86proc.}
  func mm256_broadcast_sd(a: ptr cdouble): m256i {.
       importc: "_mm256_broadcast_sd", x86proc.}
  func mm256_set_epi64x(e3, e2, e1, e0: uint64): m256i {.
       importc: "_mm256_set_epi64x", x86proc.}
  func mm256_or_si256(a, b: m256i): m256i {.
       importc: "_mm256_or_si256", x86proc.}
  func mm256_slli_epi64(a: m256i, imm8: uint32): m256i {.
       importc: "_mm256_slli_epi64", x86proc.}
  func mm256_srli_epi64(a: m256i, imm8: uint32): m256i {.
       importc: "_mm256_srli_epi64", x86proc.}
  func mm256_shuffle_epi8(a, b: m256i): m256i {.
       importc: "_mm256_shuffle_epi8", x86proc.}
  func mm256_store_si256(m: ptr m256i, a: m256i) {.
       importc: "_mm256_store_si256", x86proc.}
  func mm256_storeu_si256(m: ptr m256i, a: m256i) {.
       importc: "_mm256_storeu_si256", x86proc.}
  func mm256_storeu2_m128d(hi: ptr cdouble, lo: ptr cdouble, a: m256i) {.
       importc: "_mm256_storeu2_m128d", x86proc.}
  func mm256_xor_si256(a, b: m256i): m256i {.
       importc: "_mm256_xor_si256", x86proc.}
  func mm256_unpacklo_epi64(a, b: m256i): m256i {.
       importc: "_mm256_unpacklo_epi64", x86proc.}
  func mm256_unpackhi_epi64(a, b: m256i): m256i {.
       importc: "_mm256_unpackhi_epi64", x86proc.}
  func mm256_permute2f128_ps(a, b: m256i, imm8: uint32) {.
       importc: "_mm256_permute2f128_ps", x86proc.}
  func mm256_shuffle_pd(a, b: m256i, imm8: uint32) {.
       importc: "_mm256_shuffle_pd", x86proc.}

  let
    rho8 {.align(64).} = Rho8
    rho56 {.align(64).} = Rho56

  template ROL64in256(a: m256i, o: uint32): m256i =
    mm256_or_si256(mm256_slli_epi64(a, o), _mm256_srli_epi64(a, 64'u32 - o))
  template ROL64in2568(a: m256i): m256i =
    mm256_shuffle_epi8(mm256_load_si256(cast[ptr m256i](addr rho8)))
  template ROL64in25656(a: m256i): m256i =
    mm256_shuffle_epi8(mm256_load_si256(cast[ptr m256i](addr rho56)))


    #define ROL64in256(d, a, o)     d = _mm256_or_si256(_mm256_slli_epi64(a, o), _mm256_srli_epi64(a, 64-(o)))
    #define ROL64in256_8(d, a)      d = _mm256_shuffle_epi8(a, CONST256(rho8))
    #define ROL64in256_56(d, a)     d = _mm256_shuffle_epi8(a, CONST256(rho56))
