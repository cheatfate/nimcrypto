import nimcrypto/utils, nimcrypto/bcmode, nimcrypto/rijndael
import unittest

const
  allP = [
    "6BC1BEE22E409F96E93D7E117393172A", "AE2D8A571E03AC9C9EB76FAC45AF8E51",
    "30C81C46A35CE411E5FBC1191A0A52EF", "F69F2445DF4F9B17AD2B417BE66C3710"
  ]
  all128K = "2B7E151628AED2A6ABF7158809CF4F3C"
  all192K = "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B"
  all256K = "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4"

  # ECB test vectors
  ecb128E = [
    "3AD77BB40D7A3660A89ECAF32466EF97", "F5D3D58503B9699DE785895A96FDBAAF",
    "43B1CD7F598ECE23881B00E3ED030688", "7B0C785E27E8AD3F8223207104725DD4"
  ]
  ecb192E = [
    "BD334F1D6E45F25FF712A214571FA5CC", "974104846D0AD3AD7734ECB3ECEE4EEF",
    "EF7AFD2270E2E60ADCE0BA2FACE6444E", "9A4B41BA738D6C72FB16691603C18E0E"
  ]
  ecb256E = [
    "F3EED1BDB5D2A03C064B5A7E3DB181F8", "591CCB10D410ED26DC5BA74A31362870",
    "B6ED21B99CA6F4F9F153E7B1BEAFED1D", "23304B7A39F9F3FF067D8D8F9E24ECC7"
  ]
  # CBC test vectors
  cbcIV = "000102030405060708090A0B0C0D0E0F"
  cbc128E = [
    "7649ABAC8119B246CEE98E9B12E9197D", "5086CB9B507219EE95DB113A917678B2",
    "73BED6B8E3C1743B7116E69E22229516", "3FF1CAA1681FAC09120ECA307586E1A7"
  ]
  cbc192E = [
    "4F021DB243BC633D7178183A9FA071E8", "B4D9ADA9AD7DEDF4E5E738763F69145A",
    "571B242012FB7AE07FA9BAAC3DF102E0", "08B0E27988598881D920A9E64F5615CD"
  ]
  cbc256E = [
    "F58C4C04D6E5F1BA779EABFB5F7BFBD6", "9CFC4E967EDB808D679F777BC6702C7D",
    "39F23369A9D9BACFA530E26304231461", "B2EB05E2C39BE9FCDA6C19078C6A9D1B"
  ]
  # OFB test vectors
  ofbIV = "000102030405060708090A0B0C0D0E0F"
  ofb128E = [
    "3B3FD92EB72DAD20333449F8E83CFB4A", "7789508D16918F03F53C52DAC54ED825",
    "9740051E9C5FECF64344F7A82260EDCC", "304C6528F659C77866A510D9C1D6AE5E"
  ]
  ofb192E = [
    "CDC80D6FDDF18CAB34C25909C99A4174", "FCC28B8D4C63837C09E81700C1100401",
    "8D9A9AEAC0F6596F559C6D4DAF59A5F2", "6D9F200857CA6C3E9CAC524BD9ACC92A"
  ]
  ofb256E = [
    "DC7E84BFDA79164B7ECD8486985D3860", "4FEBDC6740D20B3AC88F6AD82A4FB08D",
    "71AB47A086E86EEDF39D1C5BBA97C408", "0126141D67F37BE8538F5A8BE740E484"
  ]
  # CFB test vectors
  cfbIV = "000102030405060708090A0B0C0D0E0F"
  cfb128E = [
    "3B3FD92EB72DAD20333449F8E83CFB4A", "C8A64537A0B3A93FCDE3CDAD9F1CE58B",
    "26751F67A3CBB140B1808CF187A4F4DF", "C04B05357C5D1C0EEAC4C66F9FF7F2E6"
  ]
  cfb192E = [
    "CDC80D6FDDF18CAB34C25909C99A4174", "67CE7F7F81173621961A2B70171D3D7A",
    "2E1E8A1DD59B88B1C8E60FED1EFAC4C9", "C05F9F9CA9834FA042AE8FBA584B09FF"
  ]
  cfb256E = [
    "DC7E84BFDA79164B7ECD8486985D3860", "39FFED143B28B1C832113C6331E5407B",
    "DF10132415E54B92A13ED0A8267AE2F9", "75A385741AB9CEF82031623D55B1E471"
  ]
  # CTR test vectors
  ctrIV = "F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
  ctr128E = [
    "874D6191B620E3261BEF6864990DB6CE", "9806F66B7970FDFF8617187BB9FFFDFF",
    "5AE4DF3EDBD5D35E5B4F09020DB03EAB", "1E031DDA2FBE03D1792170A0F3009CEE"
  ]
  ctr192E = [
    "1ABC932417521CA24F2B0459FE7E6E0B", "090339EC0AA6FAEFD5CCC2C6F4CE8E94",
    "1E36B26BD1EBC670D1BD1D665620ABF7", "4F78A7F6D29809585A97DAEC58C6B050"
  ]
  ctr256E = [
    "601EC313775789A5B7A7F504BBF3D228", "F443E3CA4D62B59ACA84E990CACAF5C5",
    "2B0930DAA23DE94CE87017BA2D84988D", "DFC9C58DB67AADA613C2DD08457941A6"
  ]

suite "Block cipher modes Tests":
  test "AES-128/192/256-ECB/CBC/OFB/CFB/CTR block sizes":
    var ecb128: ECB[aes128]
    var ecb192: ECB[aes192]
    var ecb256: ECB[aes256]
    var cbc128: CBC[aes128]
    var cbc192: CBC[aes192]
    var cbc256: CBC[aes256]
    var ofb128: OFB[aes128]
    var ofb192: OFB[aes192]
    var ofb256: OFB[aes256]
    var cfb128: CFB[aes128]
    var cfb192: CFB[aes192]
    var cfb256: CFB[aes256]
    var ctr128: CTR[aes128]
    var ctr192: CTR[aes192]
    var ctr256: CTR[aes256]
    check:
      ecb128.sizeBlock == aes128.sizeBlock
      ecb192.sizeBlock == aes192.sizeBlock
      ecb256.sizeBlock == aes256.sizeBlock
      cbc128.sizeBlock == aes128.sizeBlock
      cbc192.sizeBlock == aes192.sizeBlock
      cbc256.sizeBlock == aes256.sizeBlock
      ofb128.sizeBlock == aes128.sizeBlock
      ofb192.sizeBlock == aes192.sizeBlock
      ofb256.sizeBlock == aes256.sizeBlock
      cfb128.sizeBlock == aes128.sizeBlock
      cfb192.sizeBlock == aes192.sizeBlock
      cfb256.sizeBlock == aes256.sizeBlock
      ctr128.sizeBlock == aes128.sizeBlock
      ctr192.sizeBlock == aes192.sizeBlock
      ctr256.sizeBlock == aes256.sizeBlock

  test "AES-128/192/256-ECB/CBC/OFB/CFB/CTR key sizes":
    var ecb128: ECB[aes128]
    var ecb192: ECB[aes192]
    var ecb256: ECB[aes256]
    var cbc128: CBC[aes128]
    var cbc192: CBC[aes192]
    var cbc256: CBC[aes256]
    var ofb128: OFB[aes128]
    var ofb192: OFB[aes192]
    var ofb256: OFB[aes256]
    var cfb128: CFB[aes128]
    var cfb192: CFB[aes192]
    var cfb256: CFB[aes256]
    var ctr128: CTR[aes128]
    var ctr192: CTR[aes192]
    var ctr256: CTR[aes256]
    check:
      ecb128.sizeKey == aes128.sizeKey
      ecb192.sizeKey == aes192.sizeKey
      ecb256.sizeKey == aes256.sizeKey
      cbc128.sizeKey == aes128.sizeKey
      cbc192.sizeKey == aes192.sizeKey
      cbc256.sizeKey == aes256.sizeKey
      ofb128.sizeKey == aes128.sizeKey
      ofb192.sizeKey == aes192.sizeKey
      ofb256.sizeKey == aes256.sizeKey
      cfb128.sizeKey == aes128.sizeKey
      cfb192.sizeKey == aes192.sizeKey
      cfb256.sizeKey == aes256.sizeKey
      ctr128.sizeKey == aes128.sizeKey
      ctr192.sizeKey == aes192.sizeKey
      ctr256.sizeKey == aes256.sizeKey

  test "AES-128-ECB test vectors":
    var key = fromHex(all128K)
    var ctx1, ctx2, ctx3, ctx4: ECB[aes128]
    ctx1.init(addr key[0])
    ctx2.init(addr key[0])
    ctx3.init(key)
    ctx4.init(key)
    for i in 0..3:
      var plain = fromHex(allP[i])
      let length = len(plain)
      var ecrypt = newSeq[uint8](length)
      var dcrypt = newSeq[uint8](length)
      ctx1.encrypt(addr plain[0], addr ecrypt[0], uint(length))
      ctx2.decrypt(addr ecrypt[0], addr dcrypt[0], uint(length))
      check:
        toHex(ecrypt) == ecb128E[i]
        toHex(dcrypt) == allP[i]
      burnMem(ecrypt)
      burnMem(dcrypt)
      ctx3.encrypt(plain, ecrypt)
      ctx4.decrypt(ecrypt, dcrypt)
      check:
        toHex(ecrypt) == ecb128E[i]
        toHex(dcrypt) == allP[i]
    ctx1.clear()
    ctx2.clear()
    ctx3.clear()
    ctx4.clear()
    check:
      ctx1.isFullZero() == true
      ctx2.isFullZero() == true
      ctx3.isFullZero() == true
      ctx4.isFullZero() == true

  test "AES-192-ECB test vectors":
    var key = fromHex(all192K)
    var ctx1, ctx2, ctx3, ctx4: ECB[aes192]
    ctx1.init(addr key[0])
    ctx2.init(addr key[0])
    ctx3.init(key)
    ctx4.init(key)
    for i in 0..3:
      var plain = fromHex(allP[i])
      let length = len(plain)
      var ecrypt = newSeq[uint8](length)
      var dcrypt = newSeq[uint8](length)
      ctx1.encrypt(addr plain[0], addr ecrypt[0], uint(length))
      ctx2.decrypt(addr ecrypt[0], addr dcrypt[0], uint(length))
      check:
        toHex(ecrypt) == ecb192E[i]
        toHex(dcrypt) == allP[i]
      burnMem(ecrypt)
      burnMem(dcrypt)
      ctx3.encrypt(plain, ecrypt)
      ctx4.decrypt(ecrypt, dcrypt)
      check:
        toHex(ecrypt) == ecb192E[i]
        toHex(dcrypt) == allP[i]
    ctx1.clear()
    ctx2.clear()
    ctx3.clear()
    ctx4.clear()
    check:
      ctx1.isFullZero() == true
      ctx2.isFullZero() == true
      ctx3.isFullZero() == true
      ctx4.isFullZero() == true

  test "AES-256-ECB test vectors":
    var key = fromHex(all256K)
    var ctx1, ctx2, ctx3, ctx4: ECB[aes256]
    ctx1.init(addr key[0])
    ctx2.init(addr key[0])
    ctx3.init(key)
    ctx4.init(key)
    for i in 0..3:
      var plain = fromHex(allP[i])
      let length = len(plain)
      var ecrypt = newSeq[uint8](length)
      var dcrypt = newSeq[uint8](length)
      ctx1.encrypt(addr plain[0], addr ecrypt[0], uint(length))
      ctx2.decrypt(addr ecrypt[0], addr dcrypt[0], uint(length))
      check:
        toHex(ecrypt) == ecb256E[i]
        toHex(dcrypt) == allP[i]
      burnMem(ecrypt)
      burnMem(dcrypt)
      ctx3.encrypt(plain, ecrypt)
      ctx4.decrypt(ecrypt, dcrypt)
      check:
        toHex(ecrypt) == ecb256E[i]
        toHex(dcrypt) == allP[i]
    ctx1.clear()
    ctx2.clear()
    ctx3.clear()
    ctx4.clear()
    check:
      ctx1.isFullZero() == true
      ctx2.isFullZero() == true
      ctx3.isFullZero() == true
      ctx4.isFullZero() == true

  test "AES-128-CBC test vectors":
    var key = fromHex(all128K)
    var iv = fromHex(cbcIV)
    var ctx1, ctx2, ctx3, ctx4: CBC[aes128]
    ctx1.init(addr key[0], addr iv[0])
    ctx2.init(addr key[0], addr iv[0])
    ctx3.init(key, iv)
    ctx4.init(key, iv)
    for i in 0..3:
      var plain = fromHex(allP[i])
      let length = len(plain)
      var ecrypt = newSeq[uint8](length)
      var dcrypt = newSeq[uint8](length)
      ctx1.encrypt(addr plain[0], addr ecrypt[0], uint(length))
      ctx2.decrypt(addr ecrypt[0], addr dcrypt[0], uint(length))
      check:
        toHex(ecrypt) == cbc128E[i]
        toHex(dcrypt) == allP[i]
      burnMem(ecrypt)
      burnMem(dcrypt)
      ctx3.encrypt(plain, ecrypt)
      ctx4.decrypt(ecrypt, dcrypt)
      check:
        toHex(ecrypt) == cbc128E[i]
        toHex(dcrypt) == allP[i]
    ctx1.clear()
    ctx2.clear()
    ctx3.clear()
    ctx4.clear()
    check:
      ctx1.isFullZero() == true
      ctx2.isFullZero() == true
      ctx3.isFullZero() == true
      ctx4.isFullZero() == true

  test "AES-192-CBC test vectors":
    var key = fromHex(all192K)
    var iv = fromHex(cbcIV)
    var ctx1, ctx2, ctx3, ctx4: CBC[aes192]
    ctx1.init(addr key[0], addr iv[0])
    ctx2.init(addr key[0], addr iv[0])
    ctx3.init(key, iv)
    ctx4.init(key, iv)
    for i in 0..3:
      var plain = fromHex(allP[i])
      let length = len(plain)
      var ecrypt = newSeq[uint8](length)
      var dcrypt = newSeq[uint8](length)
      ctx1.encrypt(addr plain[0], addr ecrypt[0], uint(length))
      ctx2.decrypt(addr ecrypt[0], addr dcrypt[0], uint(length))
      check:
        toHex(ecrypt) == cbc192E[i]
        toHex(dcrypt) == allP[i]
      burnMem(ecrypt)
      burnMem(dcrypt)
      ctx3.encrypt(plain, ecrypt)
      ctx4.decrypt(ecrypt, dcrypt)
      check:
        toHex(ecrypt) == cbc192E[i]
        toHex(dcrypt) == allP[i]
    ctx1.clear()
    ctx2.clear()
    ctx3.clear()
    ctx4.clear()
    check:
      ctx1.isFullZero() == true
      ctx2.isFullZero() == true
      ctx3.isFullZero() == true
      ctx4.isFullZero() == true

  test "AES-256-CBC test vectors":
    var key = fromHex(all256K)
    var iv = fromHex(cbcIV)
    var ctx1, ctx2, ctx3, ctx4: CBC[aes256]
    ctx1.init(addr key[0], addr iv[0])
    ctx2.init(addr key[0], addr iv[0])
    ctx3.init(key, iv)
    ctx4.init(key, iv)
    for i in 0..3:
      var plain = fromHex(allP[i])
      let length = len(plain)
      var ecrypt = newSeq[uint8](length)
      var dcrypt = newSeq[uint8](length)
      ctx1.encrypt(addr plain[0], addr ecrypt[0], uint(length))
      ctx2.decrypt(addr ecrypt[0], addr dcrypt[0], uint(length))
      check:
        toHex(ecrypt) == cbc256E[i]
        toHex(dcrypt) == allP[i]
      burnMem(ecrypt)
      burnMem(dcrypt)
      ctx3.encrypt(plain, ecrypt)
      ctx4.decrypt(ecrypt, dcrypt)
      check:
        toHex(ecrypt) == cbc256E[i]
        toHex(dcrypt) == allP[i]
    ctx1.clear()
    ctx2.clear()
    ctx3.clear()
    ctx4.clear()
    check:
      ctx1.isFullZero() == true
      ctx2.isFullZero() == true
      ctx3.isFullZero() == true
      ctx4.isFullZero() == true

  test "AES-128-OFB test vectors":
    var key = fromHex(all128K)
    var iv = fromHex(ofbIV)
    var ctx1, ctx2, ctx3, ctx4: OFB[aes128]
    ctx1.init(addr key[0], addr iv[0])
    ctx2.init(addr key[0], addr iv[0])
    ctx3.init(key, iv)
    ctx4.init(key, iv)
    for i in 0..3:
      var plain = fromHex(allP[i])
      let length = len(plain)
      var ecrypt = newSeq[uint8](length)
      var dcrypt = newSeq[uint8](length)
      ctx1.encrypt(addr plain[0], addr ecrypt[0], uint(length))
      ctx2.decrypt(addr ecrypt[0], addr dcrypt[0], uint(length))
      check:
        toHex(ecrypt) == ofb128E[i]
        toHex(dcrypt) == allP[i]
      burnMem(ecrypt)
      burnMem(dcrypt)
      ctx3.encrypt(plain, ecrypt)
      ctx4.decrypt(ecrypt, dcrypt)
      check:
        toHex(ecrypt) == ofb128E[i]
        toHex(dcrypt) == allP[i]
    ctx1.clear()
    ctx2.clear()
    ctx3.clear()
    ctx4.clear()
    check:
      ctx1.isFullZero() == true
      ctx2.isFullZero() == true
      ctx3.isFullZero() == true
      ctx4.isFullZero() == true

  test "AES-192-OFB test vectors":
    var key = fromHex(all192K)
    var iv = fromHex(ofbIV)
    var ctx1, ctx2, ctx3, ctx4: OFB[aes192]
    ctx1.init(addr key[0], addr iv[0])
    ctx2.init(addr key[0], addr iv[0])
    ctx3.init(key, iv)
    ctx4.init(key, iv)
    for i in 0..3:
      var plain = fromHex(allP[i])
      let length = len(plain)
      var ecrypt = newSeq[uint8](length)
      var dcrypt = newSeq[uint8](length)
      ctx1.encrypt(addr plain[0], addr ecrypt[0], uint(length))
      ctx2.decrypt(addr ecrypt[0], addr dcrypt[0], uint(length))
      check:
        toHex(ecrypt) == ofb192E[i]
        toHex(dcrypt) == allP[i]
      burnMem(ecrypt)
      burnMem(dcrypt)
      ctx3.encrypt(plain, ecrypt)
      ctx4.decrypt(ecrypt, dcrypt)
      check:
        toHex(ecrypt) == ofb192E[i]
        toHex(dcrypt) == allP[i]
    ctx1.clear()
    ctx2.clear()
    ctx3.clear()
    ctx4.clear()
    check:
      ctx1.isFullZero() == true
      ctx2.isFullZero() == true
      ctx3.isFullZero() == true
      ctx4.isFullZero() == true

  test "AES-256-OFB test vectors":
    var key = fromHex(all256K)
    var iv = fromHex(ofbIV)
    var ctx1, ctx2, ctx3, ctx4: OFB[aes256]
    ctx1.init(addr key[0], addr iv[0])
    ctx2.init(addr key[0], addr iv[0])
    ctx3.init(key, iv)
    ctx4.init(key, iv)
    for i in 0..3:
      var plain = fromHex(allP[i])
      let length = len(plain)
      var ecrypt = newSeq[uint8](length)
      var dcrypt = newSeq[uint8](length)
      ctx1.encrypt(addr plain[0], addr ecrypt[0], uint(length))
      ctx2.decrypt(addr ecrypt[0], addr dcrypt[0], uint(length))
      check:
        toHex(ecrypt) == ofb256E[i]
        toHex(dcrypt) == allP[i]
      burnMem(ecrypt)
      burnMem(dcrypt)
      ctx3.encrypt(plain, ecrypt)
      ctx4.decrypt(ecrypt, dcrypt)
      check:
        toHex(ecrypt) == ofb256E[i]
        toHex(dcrypt) == allP[i]
    ctx1.clear()
    ctx2.clear()
    ctx3.clear()
    ctx4.clear()
    check:
      ctx1.isFullZero() == true
      ctx2.isFullZero() == true
      ctx3.isFullZero() == true
      ctx4.isFullZero() == true

  test "AES-128-CFB test vectors":
    var key = fromHex(all128K)
    var iv = fromHex(cfbIV)
    var ctx1, ctx2, ctx3, ctx4: CFB[aes128]
    ctx1.init(addr key[0], addr iv[0])
    ctx2.init(addr key[0], addr iv[0])
    ctx3.init(key, iv)
    ctx4.init(key, iv)
    for i in 0..3:
      var plain = fromHex(allP[i])
      let length = len(plain)
      var ecrypt = newSeq[uint8](length)
      var dcrypt = newSeq[uint8](length)
      ctx1.encrypt(addr plain[0], addr ecrypt[0], uint(length))
      ctx2.decrypt(addr ecrypt[0], addr dcrypt[0], uint(length))
      check:
        toHex(ecrypt) == cfb128E[i]
        toHex(dcrypt) == allP[i]
      burnMem(ecrypt)
      burnMem(dcrypt)
      ctx3.encrypt(plain, ecrypt)
      ctx4.decrypt(ecrypt, dcrypt)
      check:
        toHex(ecrypt) == cfb128E[i]
        toHex(dcrypt) == allP[i]
    ctx1.clear()
    ctx2.clear()
    ctx3.clear()
    ctx4.clear()
    check:
      ctx1.isFullZero() == true
      ctx2.isFullZero() == true
      ctx3.isFullZero() == true
      ctx4.isFullZero() == true

  test "AES-192-CFB test vectors":
    var key = fromHex(all192K)
    var iv = fromHex(cfbIV)
    var ctx1, ctx2, ctx3, ctx4: CFB[aes192]
    ctx1.init(addr key[0], addr iv[0])
    ctx2.init(addr key[0], addr iv[0])
    ctx3.init(key, iv)
    ctx4.init(key, iv)
    for i in 0..3:
      var plain = fromHex(allP[i])
      let length = len(plain)
      var ecrypt = newSeq[uint8](length)
      var dcrypt = newSeq[uint8](length)
      ctx1.encrypt(addr plain[0], addr ecrypt[0], uint(length))
      ctx2.decrypt(addr ecrypt[0], addr dcrypt[0], uint(length))
      check:
        toHex(ecrypt) == cfb192E[i]
        toHex(dcrypt) == allP[i]
      burnMem(ecrypt)
      burnMem(dcrypt)
      ctx3.encrypt(plain, ecrypt)
      ctx4.decrypt(ecrypt, dcrypt)
      check:
        toHex(ecrypt) == cfb192E[i]
        toHex(dcrypt) == allP[i]
    ctx1.clear()
    ctx2.clear()
    ctx3.clear()
    ctx4.clear()
    check:
      ctx1.isFullZero() == true
      ctx2.isFullZero() == true
      ctx3.isFullZero() == true
      ctx4.isFullZero() == true

  test "AES-256-CFB test vectors":
    var key = fromHex(all256K)
    var iv = fromHex(cfbIV)
    var ctx1, ctx2, ctx3, ctx4: CFB[aes256]
    ctx1.init(addr key[0], addr iv[0])
    ctx2.init(addr key[0], addr iv[0])
    ctx3.init(key, iv)
    ctx4.init(key, iv)
    for i in 0..3:
      var plain = fromHex(allP[i])
      let length = len(plain)
      var ecrypt = newSeq[uint8](length)
      var dcrypt = newSeq[uint8](length)
      ctx1.encrypt(addr plain[0], addr ecrypt[0], uint(length))
      ctx2.decrypt(addr ecrypt[0], addr dcrypt[0], uint(length))
      check:
        toHex(ecrypt) == cfb256E[i]
        toHex(dcrypt) == allP[i]
      burnMem(ecrypt)
      burnMem(dcrypt)
      ctx3.encrypt(plain, ecrypt)
      ctx4.decrypt(ecrypt, dcrypt)
      check:
        toHex(ecrypt) == cfb256E[i]
        toHex(dcrypt) == allP[i]
    ctx1.clear()
    ctx2.clear()
    ctx3.clear()
    ctx4.clear()
    check:
      ctx1.isFullZero() == true
      ctx2.isFullZero() == true
      ctx3.isFullZero() == true
      ctx4.isFullZero() == true

  test "AES-128-CTR test vectors":
    var key = fromHex(all128K)
    var iv = fromHex(ctrIV)
    var ctx1, ctx2, ctx3, ctx4: CTR[aes128]
    ctx1.init(addr key[0], addr iv[0])
    ctx2.init(addr key[0], addr iv[0])
    ctx3.init(key, iv)
    ctx4.init(key, iv)
    for i in 0..3:
      var plain = fromHex(allP[i])
      let length = len(plain)
      var ecrypt = newSeq[uint8](length)
      var dcrypt = newSeq[uint8](length)
      ctx1.encrypt(addr plain[0], addr ecrypt[0], uint(length))
      ctx2.decrypt(addr ecrypt[0], addr dcrypt[0], uint(length))
      check:
        toHex(ecrypt) == ctr128E[i]
        toHex(dcrypt) == allP[i]
      burnMem(ecrypt)
      burnMem(dcrypt)
      ctx3.encrypt(plain, ecrypt)
      ctx4.encrypt(ecrypt, dcrypt)
      check:
        toHex(ecrypt) == ctr128E[i]
        toHex(dcrypt) == allP[i]
    ctx1.clear()
    ctx2.clear()
    ctx3.clear()
    ctx4.clear()
    check:
      ctx1.isFullZero() == true
      ctx2.isFullZero() == true
      ctx3.isFullZero() == true
      ctx4.isFullZero() == true

  test "AES-192-CTR test vectors":
    var key = fromHex(all192K)
    var iv = fromHex(ctrIV)
    var ctx1, ctx2, ctx3, ctx4: CTR[aes192]
    ctx1.init(addr key[0], addr iv[0])
    ctx2.init(addr key[0], addr iv[0])
    ctx3.init(key, iv)
    ctx4.init(key, iv)
    for i in 0..3:
      var plain = fromHex(allP[i])
      let length = len(plain)
      var ecrypt = newSeq[uint8](length)
      var dcrypt = newSeq[uint8](length)
      ctx1.encrypt(addr plain[0], addr ecrypt[0], uint(length))
      ctx2.decrypt(addr ecrypt[0], addr dcrypt[0], uint(length))
      check:
        toHex(ecrypt) == ctr192E[i]
        toHex(dcrypt) == allP[i]
      burnMem(ecrypt)
      burnMem(dcrypt)
      ctx3.encrypt(plain, ecrypt)
      ctx4.decrypt(ecrypt, dcrypt)
      check:
        toHex(ecrypt) == ctr192E[i]
        toHex(dcrypt) == allP[i]
    ctx1.clear()
    ctx2.clear()
    ctx3.clear()
    ctx4.clear()
    check:
      ctx1.isFullZero() == true
      ctx2.isFullZero() == true
      ctx3.isFullZero() == true
      ctx4.isFullZero() == true

  test "AES-256-CTR test vectors":
    var key = fromHex(all256K)
    var iv = fromHex(ctrIV)
    var ctx1, ctx2, ctx3, ctx4: CTR[aes256]
    ctx1.init(addr key[0], addr iv[0])
    ctx2.init(addr key[0], addr iv[0])
    ctx3.init(key, iv)
    ctx4.init(key, iv)
    for i in 0..3:
      var plain = fromHex(allP[i])
      let length = len(plain)
      var ecrypt = newSeq[uint8](length)
      var dcrypt = newSeq[uint8](length)
      ctx1.encrypt(addr plain[0], addr ecrypt[0], uint(length))
      ctx2.decrypt(addr ecrypt[0], addr dcrypt[0], uint(length))
      check:
        toHex(ecrypt) == ctr256E[i]
        toHex(dcrypt) == allP[i]
      burnMem(ecrypt)
      burnMem(dcrypt)
      ctx3.encrypt(plain, ecrypt)
      ctx4.decrypt(ecrypt, dcrypt)
      check:
        toHex(ecrypt) == ctr256E[i]
        toHex(dcrypt) == allP[i]
    ctx1.clear()
    ctx2.clear()
    ctx3.clear()
    ctx4.clear()
    check:
      ctx1.isFullZero() == true
      ctx2.isFullZero() == true
      ctx3.isFullZero() == true
      ctx4.isFullZero() == true
