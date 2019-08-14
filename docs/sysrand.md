
This module implements interface to operation system's random number generator.

**Windows** using BCryptGenRandom (if available), CryptGenRandom(PROV\_INTEL\_SEC) (if available), RtlGenRandom.

RtlGenRandom (available from Windows XP) BCryptGenRandom (available from Windows Vista SP1) CryptGenRandom(PROV\_INTEL\_SEC) (only when Intel SandyBridge CPU is available).

**Linux** using genrandom (if available), `/dev/urandom`.

**OpenBSD** using getentropy.

**NetBSD, FreeBSD, MacOS, Solaris** using `/dev/urandom`.
