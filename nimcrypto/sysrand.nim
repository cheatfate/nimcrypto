#
#
#                    NimCrypto
#        (c) Copyright 2018 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements interface to operation system's random number
## generator.
##
## ``Windows`` using BCryptGenRandom (if available),
## CryptGenRandom(PROV_INTEL_SEC) (if available), RtlGenRandom.
##
## RtlGenRandom (available from Windows XP)
## BCryptGenRandom (available from Windows Vista SP1)
## CryptGenRandom(PROV_INTEL_SEC) (only when Intel SandyBridge
## CPU is available).
##
## ``Linux`` using genrandom (if available), `/dev/urandom`.
##
## ``OpenBSD`` using getentropy.
##
## ``NetBSD``, ``FreeBSD``, ``MacOS``, ``Solaris`` using `/dev/urandom`.

{.deadCodeElim:on.}

when defined(posix):
  import os, posix

  proc urandomRead(pbytes: pointer, nbytes: int): int =
    result = -1
    var st: Stat
    let fd = posix.open("/dev/urandom", posix.O_RDONLY)
    if fd != -1:
      if posix.fstat(fd, st) != -1 and S_ISCHR(st.st_mode):
        result = 0
        while result < nbytes:
          var p = cast[pointer](cast[uint]((pbytes)) + uint(result))
          var res = posix.read(fd, p, nbytes - result)
          if res > 0:
            result += res
          elif res == 0:
            break
          else:
            if osLastError().int32 != EINTR:
              result = -1
              break
      discard posix.close(fd)

when defined(openbsd):
  import posix, os

  proc getentropy(pBytes: pointer, nBytes: int): cint
       {.importc: "getentropy", header: "<unistd.h>".}

  proc randomBytes*(pbytes: pointer, nbytes: int): int =
    var p: pointer
    while result < nbytes:
      p = cast[pointer](cast[uint](pbytes) + uint(result))
      let res = getentropy(p, nbytes - result)
      if res > 0:
        result += res
      elif res == 0:
        break
      else:
        if osLastError().int32 != EINTR:
          result = -1
          break

    if result == -1:
      result = urandomRead(pbytes, nbytes)
    elif result < nbytes:
      p = cast[pointer](cast[uint](pbytes) + uint(result))
      let res = urandomRead(p, nbytes - result)
      if res != -1:
        result += res

elif defined(linux):
  import posix, os
  when defined(i386):
    const SYS_getrandom = 355
  elif defined(powerpc64) or defined(powerpc64el) or defined(powerpc):
    const SYS_getrandom = 359
  elif defined(arm64):
    const SYS_getrandom = 278
  elif defined(arm):
    const SYS_getrandom = 384
  elif defined(amd64):
    const SYS_getrandom = 318
  elif defined(mips):
    when sizeof(int) == 8:
      const SYS_getrandom = 4000 + 313
    else:
      const SYS_getrandom = 4000 + 353
  else:
    const SYS_getrandom = 0
  const
    GRND_NONBLOCK = 1

  type
    SystemRng = ref object of RootRef
      getRandomPresent: bool

  proc syscall(number: clong): clong {.importc: "syscall",
       header: """#include <unistd.h>
                  #include <sys/syscall.h>""", varargs, discardable.}

  var gSystemRng {.threadvar.}: SystemRng ## System thread global RNG

  proc newSystemRNG(): SystemRng =
    result = SystemRng()

    if SYS_getrandom != 0:
      var data: int
      result.getRandomPresent = true
      let res = syscall(SYS_getrandom, addr data, 1, GRND_NONBLOCK)
      if res == -1:
        let err = osLastError().int32
        if err == ENOSYS or err == EPERM:
          result.getRandomPresent = false

  proc getSystemRNG(): SystemRng =
    if gSystemRng.isNil: gSystemRng = newSystemRng()
    result = gSystemRng

  proc randomBytes*(pbytes: pointer, nbytes: int): int =
    var p: pointer
    let srng = getSystemRNG()
    if srng.getRandomPresent:
      while result < nbytes:
        p = cast[pointer](cast[uint](pbytes) + uint(result))
        let res = syscall(SYS_getrandom, pBytes, nBytes - result, 0)
        if res > 0:
          result += res
        elif res == 0:
          break
        else:
          if osLastError().int32 != EINTR:
            result = -1
            break

      if result == -1:
        result = urandomRead(pbytes, nbytes)
      elif result < nbytes:
        p = cast[pointer](cast[uint](pbytes) + uint(result))
        let res = urandomRead(p, nbytes - result)
        if res != -1:
          result += res
    else:
      result = urandomRead(pbytes, nbytes)

elif defined(windows):
  import os, winlean, dynlib

  const
    VER_GREATER_EQUAL = 3'u8
    VER_MINORVERSION = 0x0000001
    VER_MAJORVERSION = 0x0000002
    VER_SERVICEPACKMINOR = 0x0000010
    VER_SERVICEPACKMAJOR = 0x0000020
    PROV_INTEL_SEC = 22
    INTEL_DEF_PROV = "Intel Hardware Cryptographic Service Provider"
    CRYPT_VERIFYCONTEXT = 0xF0000000'i32
    CRYPT_SILENT = 0x00000040'i32
    BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002
  type
    OSVERSIONINFOEXW {.final, pure.} = object
      dwOSVersionInfoSize: DWORD
      dwMajorVersion: DWORD
      dwMinorVersion: DWORD
      dwBuildNumber: DWORD
      dwPlatformId: DWORD
      szCSDVersion: array[128, Utf16Char]
      wServicePackMajor: uint16
      wServicePackMinor: uint16
      wSuiteMask: uint16
      wProductType: byte
      wReserved: byte

    HCRYPTPROV = uint

    BCGRMPROC = proc(hAlgorithm: pointer, pBuffer: pointer, cBuffer: ULONG,
                     dwFlags: ULONG): LONG {.stdcall, gcsafe, raises:[].}
    QPCPROC = proc(hProcess: Handle, cycleTime: var uint64): WINBOOL {.
              stdcall, gcsafe, raises:[].}
    QUITPROC = proc(itime: var uint64) {.stdcall, gcsafe, raises:[].}
    QIPCPROC = proc(bufferLength: var uint32, idleTime: ptr uint64): WINBOOL {.
               stdcall, gcsafe, raises:[].}

    SystemRng = ref object of RootRef
      bCryptGenRandom: BCGRMPROC
      queryProcessCycleTime: QPCPROC
      queryUnbiasedInterruptTime: QUITPROC
      queryIdleProcessorCycleTime: QIPCPROC
      coresCount: uint32
      hIntel: HCRYPTPROV

  var gSystemRng {.threadvar.}: SystemRng ## System thread global RNG

  proc verifyVersionInfo(lpVerInfo: ptr OSVERSIONINFOEXW, dwTypeMask: DWORD,
                         dwlConditionMask: uint64): WINBOOL
       {.importc: "VerifyVersionInfoW", stdcall, dynlib: "kernel32.dll".}
  proc verSetConditionMask(conditionMask: uint64, dwTypeMask: DWORD,
                           condition: byte): uint64
       {.importc: "VerSetConditionMask", stdcall, dynlib: "kernel32.dll".}
  proc cryptAcquireContext(phProv: ptr HCRYPTPROV, pszContainer: WideCString,
                           pszProvider: WideCString, dwProvType: DWORD,
                           dwFlags: DWORD): WINBOOL
       {.importc: "CryptAcquireContextW", stdcall, dynlib: "advapi32.dll".}
  proc cryptReleaseContext(phProv: HCRYPTPROV, dwFlags: DWORD): WINBOOL
       {.importc: "CryptReleaseContext", stdcall, dynlib: "advapi32.dll".}
  proc cryptGenRandom(phProv: HCRYPTPROV, dwLen: DWORD,
                      pBuffer: pointer): WINBOOL
       {.importc: "CryptGenRandom", stdcall, dynlib: "advapi32.dll".}
  proc rtlGenRandom(bufptr: pointer, buflen: ULONG): WINBOOL
       {.importc: "SystemFunction036", stdcall, dynlib: "advapi32.dll".}

  proc isEqualOrHigher(major: int, minor: int, servicePack: int): bool =
    var mask = 0'u64
    var ov = OSVERSIONINFOEXW()
    ov.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW).DWORD
    ov.dwMajorVersion = major.DWORD
    ov.dwMinorVersion = minor.DWORD
    ov.wServicePackMajor = servicePack.uint16
    ov.wServicePackMinor = 0
    var typeMask = (VER_MAJORVERSION or VER_MINORVERSION or
                   VER_SERVICEPACKMAJOR or VER_SERVICEPACKMINOR).DWORD
    mask = verSetConditionMask(mask, VER_MAJORVERSION, VER_GREATER_EQUAL)
    mask = verSetConditionMask(mask, VER_MINORVERSION, VER_GREATER_EQUAL)
    mask = verSetConditionMask(mask, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL)
    mask = verSetConditionMask(mask, VER_SERVICEPACKMINOR, VER_GREATER_EQUAL)
    return (verifyVersionInfo(addr ov, typeMask, mask) == 1)

  proc newSystemRNG(): SystemRng =
    result = SystemRng()
    if isEqualOrHigher(6, 0, 0):
      if isEqualOrHigher(6, 0, 1):
        let lib = loadLib("bcrypt.dll")
        if lib != nil:
          var lProc = cast[BCGRMPROC](symAddr(lib, "BCryptGenRandom"))
          if not isNil(lProc):
            result.bCryptGenRandom = lProc

    var hp: HCRYPTPROV = 0
    let intelDef = newWideCString(INTEL_DEF_PROV)
    let res1 = cryptAcquireContext(addr hp, nil, intelDef, PROV_INTEL_SEC,
                                   CRYPT_VERIFYCONTEXT or CRYPT_SILENT).bool
    if res1:
      result.hIntel = hp

  proc getSystemRNG(): SystemRng =
    if gSystemRng.isNil: gSystemRng = newSystemRng()
    result = gSystemRng

  proc randomBytes*(pbytes: pointer, nbytes: int): int =
    let srng = getSystemRNG()
    result = -1
    if not isNil(srng.bCryptGenRandom):
      if srng.bCryptGenRandom(nil, pbytes, nbytes.ULONG,
                              BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0:
        result = nbytes

    if srng.hIntel != 0 and result == -1:
      if cryptGenRandom(srng.hIntel, nbytes.DWORD, pbytes) != 0:
        result = nbytes

    if result == -1:
      if rtlGenRandom(pBytes, nbytes.ULONG) != 0:
        result = nbytes

  proc randomClose*() =
    let srng = getSystemRNG()
    if srng.hIntel != 0:
      if cryptReleaseContext(srng.hIntel, 0) == 0:
        raiseOsError(osLastError())
else:
  import posix

  proc randomBytes*(pbytes: pointer, nbytes: int): int =
    result = urandomRead(pbytes, nbytes)

proc randomBytes*[T](bytes: var openarray[T]): int =
  let length = len(bytes) * sizeof(T)
  if length > 0:
    result = randomBytes(addr bytes[0], length)
    if result != -1:
      result = result div sizeof(T)
