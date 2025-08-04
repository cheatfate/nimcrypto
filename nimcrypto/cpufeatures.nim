#
#
#                    NimCrypto
#        (c) Copyright 2024 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module provides CPU cryptographic features detection.

{.push raises: [].}

type
  CpuFeature* {.pure.} = enum
    AMD64,     # AMD64 processor
    AARCH64,   # AARCH64 (ARM64) processor
    AVX,       # Intel AVX extension support
    AVX2,      # Intel AVX2 extension support
    AVX512,    # Intel AVX512 extension support
    SHA1EXT,   # SHA1 extension support
    SHA2EXT,   # SHA2-256 extension support
    SHA2BEXT,  # SHA2-512 extension support
    CRC32,     # CRC-32 extension support
    AES        # AES extension support

when defined(amd64):
  when defined(vcc):
    func getCpuid(cpuInfo: ptr uint32, funcId: uint32, subId: uint32) {.
         importc: "__cpuidex", header: "<intrin.h>".}
  else:
    func getCpuid(leaf, subleaf: uint32,
                  eax, ebx, ecx, edx: var uint32): uint32 {.
         importc: "__get_cpuid_count", header: "<cpuid.h>".}

  func cpuId(leaf, subleaf: uint32): array[4, uint32] =
    var res: array[4, uint32]
    when defined(vcc):
      getCpuid(addr res[0], leaf, subleaf)
    else:
      discard getCpuid(leaf, subleaf, res[0], res[1], res[2], res[3])
    res

  const
    BIT_SHA = 1'u32 shl 29
    REG_SHA = 1
    BIT_AVX = 1'u32 shl 28
    REG_AVX = 2
    BIT_AES = 1'u32 shl 25
    REG_AES = 2
    BIT_AVX2 = 1'u32 shl 5
    REG_AVX2 = 1
    BIT_AVX512F = 1'u32 shl 16
    REG_AVX512F = 1
    BIT_AVX512BW = 1'u32 shl 30
    REG_AVX512BW = 1
    BIT_CRC32 = 1'u32 shl 20
    REG_CRC32 = 2

  func getCpuFeatures*(): set[CpuFeature] =
    var res: set[CpuFeature]
    res.incl(CpuFeature.AMD64)
    let
      array1 = cpuId(1'u32, 0'u32)
      array7 = cpuId(7'u32, 0'u32)

    if (array1[REG_AVX] and BIT_AVX) != 0'u32:
      res.incl(CpuFeature.AVX)
    if (array1[REG_AES] and BIT_AES) != 0'u32:
      res.incl(CpuFeature.AES)
    if (array1[REG_CRC32] and BIT_CRC32) != 0'u32:
      res.incl(CpuFeature.CRC32)
    if (array7[REG_SHA] and BIT_SHA) != 0'u32:
      res.incl(CpuFeature.SHA1EXT)
      res.incl(CpuFeature.SHA2EXT)
    if (array7[REG_AVX2] and BIT_AVX2) != 0'u32:
      res.incl(CpuFeature.AVX2)
    if ((array7[REG_AVX512F] and BIT_AVX512F) != 0'u32) and
       ((array7[REG_AVX512BW] and BIT_AVX512BW) != 0'u32):
      res.incl(CpuFeature.AVX512)
    res
elif defined(arm64):
  when defined(linux):
    func getauxval(t: uint32): uint32 {.
         importc: "getauxval", header: "<sys/auxv.h>".}
    const
      AT_HWCAP = 16'u32
      HWCAP_AES = 0x08'u32
      HWCAP_SHA1 = 0x20'u32
      HWCAP_SHA2 = 0x40'u32
      HWCAP_CRC32 = 0x80'u32
      HWCAP_SHA512 = 0x200000'u32

    func getCpuFeatures*(): set[CpuFeature] =
      var res: set[CpuFeature]
      res.incl(CpuFeature.AARCH64)
      let plain = getauxval(AT_HWCAP)
      if (plain and HWCAP_AES) != 0'u32:
        res.incl(CpuFeature.AES)
      if (plain and HWCAP_SHA1) != 0'u32:
        res.incl(CpuFeature.SHA1EXT)
      if (plain and HWCAP_SHA2) != 0'u32:
        res.incl(CpuFeature.SHA2EXT)
      if (plain and HWCAP_CRC32) != 0'u32:
        res.incl(CpuFeature.CRC32)
      if (plain and HWCAP_SHA512) != 0'u32:
        res.incl(CpuFeature.SHA2BEXT)
      res
  elif defined(macos) or defined(macosx):
    func getCpuFeatures*(): set[CpuFeature] =
      ## TODO: Right now all modern aarch64 macos systems has neon extensions
      ## available, but we do not have method to detect it yet.
      {CpuFeature.AARCH64, CpuFeature.SHA2EXT, CpuFeature.SHA2BEXT,
       CpuFeature.CRC32, CpuFeature.AES}
  else:
    func getCpuFeatures*(): set[CpuFeature] =
      {}
else:
  func getCpuFeatures*(): set[CpuFeature] =
    {}

let
  nimcryptoCpuFeatures*: set[CpuFeature] = getCpuFeatures()

template defaultCpuFeatures*(): set[CpuFeature] =
  when nimvm:
    {}
  else:
    {.noSideEffect.}: nimcryptoCpuFeatures
