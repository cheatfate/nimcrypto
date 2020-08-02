import unittest

# use include here, because we want to test
# internal functions too
include ../nimcrypto/scrypt

when defined(nimHasUsed): {.used.}

const
  # these BE uint32 are copied from RFC 7914
  # test vectors octets, and I'm too lazy to
  # rewrite/reprint it into LE uint32

  inputBE = [
    0x7e879a21'u32, 0x4f3ec986'u32, 0x7ca940e6'u32, 0x41718f26'u32,
    0xbaee555b'u32, 0x8c61c1b5'u32, 0x0df84611'u32, 0x6dcd3b1d'u32,
    0xee24f319'u32, 0xdf9b3d85'u32, 0x14121e4b'u32, 0x5ac5aa32'u32,
    0x76021d29'u32, 0x09c74829'u32, 0xedebc68d'u32, 0xb8b8c25e'u32
    ]

  outputBE = [
    0xa41f859c'u32, 0x6608cc99'u32, 0x3b81cacb'u32, 0x020cef05'u32,
    0x044b2181'u32, 0xa2fd337d'u32, 0xfd7b1c63'u32, 0x96682f29'u32,
    0xb4393168'u32, 0xe3c9e6bc'u32, 0xfe6bc5b7'u32, 0xa06d96ba'u32,
    0xe424cc10'u32, 0x2c91745c'u32, 0x24ad673d'u32, 0xc7618f81'u32
  ]

  bInBE = [
    0xf7ce0b65'u32, 0x3d2d72a4'u32, 0x108cf5ab'u32, 0xe912ffdd'u32,
    0x777616db'u32, 0xbb27a70e'u32, 0x8204f3ae'u32, 0x2d0f6fad'u32,
    0x89f68f48'u32, 0x11d1e87b'u32, 0xcc3bd740'u32, 0x0a9ffd29'u32,
    0x094f0184'u32, 0x639574f3'u32, 0x9ae5a131'u32, 0x5217bcd7'u32,
    0x89499144'u32, 0x7213bb22'u32, 0x6c25b54d'u32, 0xa86370fb'u32,
    0xcd984380'u32, 0x374666bb'u32, 0x8ffcb5bf'u32, 0x40c254b0'u32,
    0x67d27c51'u32, 0xce4ad5fe'u32, 0xd829c90b'u32, 0x505a571b'u32,
    0x7f4d1cad'u32, 0x6a523cda'u32, 0x770e67bc'u32, 0xeaaf7e89'u32
  ]

  bOutBE = [
    0xa41f859c'u32, 0x6608cc99'u32, 0x3b81cacb'u32, 0x020cef05'u32,
    0x044b2181'u32, 0xa2fd337d'u32, 0xfd7b1c63'u32, 0x96682f29'u32,
    0xb4393168'u32, 0xe3c9e6bc'u32, 0xfe6bc5b7'u32, 0xa06d96ba'u32,
    0xe424cc10'u32, 0x2c91745c'u32, 0x24ad673d'u32, 0xc7618f81'u32,
    0x20edc975'u32, 0x323881a8'u32, 0x0540f64c'u32, 0x162dcd3c'u32,
    0x21077cfe'u32, 0x5f8d5fe2'u32, 0xb1a4168f'u32, 0x953678b7'u32,
    0x7d3b3d80'u32, 0x3b60e4ab'u32, 0x920996e5'u32, 0x9b4d53b6'u32,
    0x5d2a2258'u32, 0x77d5edf5'u32, 0x842cb9f1'u32, 0x4eefe425'u32
  ]

  bhex =
    "f7ce0b653d2d72a4108cf5abe912ffdd" &
    "777616dbbb27a70e8204f3ae2d0f6fad" &
    "89f68f4811d1e87bcc3bd7400a9ffd29" &
    "094f0184639574f39ae5a1315217bcd7" &
    "894991447213bb226c25b54da86370fb" &
    "cd984380374666bb8ffcb5bf40c254b0" &
    "67d27c51ce4ad5fed829c90b505a571b" &
    "7f4d1cad6a523cda770e67bceaaf7e89"

  bouthex =
    "79ccc193629debca047f0b70604bf6b6" &
    "2ce3dd4a9626e355fafc6198e6ea2b46" &
    "d58413673b99b029d665c357601fb426" &
    "a0b2f4bba200ee9f0a43d19b571a9c71" &
    "ef1142e65d5a266fddca832ce59faa7c" &
    "ac0b9cf1be2bffca300d01ee387619c4" &
    "ae12fd4438f203a0e4e1c47ec314861f" &
    "4e9087cb33396a6873e8f9d2539a4b8e"

proc swapBytes(x: var openArray[uint32]) =
  for i in 0..<x.len:
    x[i] = leSwap32(x[i])

proc swapBytes(a: var openArray[uint32], b: openArray[uint32]) =
  for i in 0..<a.len:
    a[i] = leSwap32(b[i])

suite "Scrypt KDF tests suite":
  test "salsaXor":
    var input: array[16, uint32]
    var output: array[16, uint32]
    var tmp: array[16, uint32]

    input.swapBytes(inputBE)
    salsaXor(tmp, input, 0, output, 0)
    output.swapBytes
    check output == outputBE

  test "blockMix":
    var bIn: array[32, uint32]
    var bOut: array[32, uint32]
    var bTmp: array[32, uint32]

    bIn.swapBytes(bInBE)
    blockMix(bTmp, bIn, 0, bOut, 0, 1)
    bOut.swapBytes
    check bOut == bOutBE

  test "smix":
    let
      r = 1
      N = 16
    var xy = newSeq[uint32](64*r + 32*N*r)

    var b = utils.fromHex(bhex)
    smix(b, 0, r, N, xy, 64*r)
    var bb = utils.fromHex(bouthex)
    check b == bb

  func scrypt[T, M](password: openArray[T], salt: openArray[M],
                     N, r, p, keyLen: static[int]): array[keyLen, byte] =
    let (xyvLen, bLen) = scryptCalc(N, r, p)
    var xyv = newSeq[uint32](xyvLen)
    var b = newSeq[byte](bLen)
    discard scrypt(password, salt, N, r, p, xyv, b, result)

  # again, these test vectors are copied from RFC 7914
  test "scrypt N=16, r=1, p=1, keyLen=64":
    let key = fromHex("77D6576238657B203B19CA42C18A0497F16B4844E3074AE8DFDFFA3FEDE21442" &
              "FCD0069DED0948F8326A753A0FC81F17E8D3E0FB2E0D3628CF35E20C38D18906")
    let dkey = scrypt(password="", salt="", N=16, r=1, p=1, keyLen=64)
    check key == dkey

  test "scrypt N=16, r=1, p=1, keyLen=64 (compile-time)":
    const key = fromHex("77D6576238657B203B19CA42C18A0497F16B4844E3074AE8DFDFFA3FEDE21442" &
              "FCD0069DED0948F8326A753A0FC81F17E8D3E0FB2E0D3628CF35E20C38D18906")
    const dkey = scrypt(password="", salt="", N=16, r=1, p=1, keyLen=64)
    check key == dkey

  test "scrypt N=1024, r=8, p=16, keyLen=64":
    let key = fromHex("FDBABE1C9D3472007856E7190D01E9FE7C6AD7CBC8237830E77376634B373162" &
              "2EAF30D92E22A3886FF109279D9830DAC727AFB94A83EE6D8360CBDFA2CC0640")
    let dkey = scrypt(password="password", salt="NaCl", N=1024, r=8, p=16, keyLen=64)
    check key == dkey

  test "scrypt N=16384, r=8, p=1, keyLen=64":
    let key = fromHex("7023BDCB3AFD7348461C06CD81FD38EBFDA8FBBA904F8E3EA9B543F6545DA1F2" &
              "D5432955613F0FCF62D49705242A9AF9E61E85DC0D651E40DFCF017B45575887")
    let dkey = scrypt(password="pleaseletmein", salt="SodiumChloride", N=16384, r=8, p=1, keyLen=64)
    check key == dkey

  when defined(cpu64):
    # these test vectors OOM with appveyor 32 bit
    # because of huge N
    test "scrypt N=1048576, r=8, p=1, keyLen=32":
      let key = fromHex("E277EA2CACB23EDAFC039D229B79DC13ECEDB601D99B182A9FEDBA1E2BFB4F58")
      let dkey = scrypt(password="Rabbit", salt="Mouse", N=1048576, r=8, p=1, keyLen=32)
      check key == dkey

    test "scrypt N=1048576, r=8, p=1, keyLen=64":
      let key = fromHex("2101CB9B6A511AAEADDBBE09CF70F881EC568D574A2FFD4DABE5EE9820ADAA47" &
                "8E56FD8F4BA5D09FFA1C6D927C40F4C337304049E8A952FBCBF45C6FA77A41A4")
      let dkey = scrypt(password="pleaseletmein", salt="SodiumChloride", N=1048576, r=8, p=1, keyLen=64)
      check key == dkey

  test "string vs openarray[byte]":
    let stringarg = scrypt(password="password", salt="NaCl", N=1024, r=8, p=16, keyLen=32)
    let openarrayarg = scrypt(fromHex("70617373776F7264"), fromHex("4E61436C"), N=1024, r=8, p=16, keyLen=32)
    check stringarg == openarrayarg
