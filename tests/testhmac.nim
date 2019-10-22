import nimcrypto/hmac, nimcrypto/hash, nimcrypto/utils
import nimcrypto/sha2, nimcrypto/ripemd, nimcrypto/keccak
import nimcrypto/sha
import unittest

when defined(nimHasUsed): {.used.}

suite "HMAC Tests":
  # SHA1 test vectors
  # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA1.pdf

  const sha1keys = [
    """000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
       202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F""",
    "000102030405060708090A0B0C0D0E0F10111213",
    """000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
       202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F
       404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F
       60616263"""
  ]

  const sha1data = [
    "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E",
    "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E",
    "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"
  ]

  const sha1digests = [
    "5FD596EE78D5553C8FF4E72D266DFD192366DA29",
    "4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807",
    "2D51B2F7750E410584662E38F133435F4C4FD42A"
  ]

  # RIPEMD 128/160 test vectors
  # https://tools.ietf.org/html/rfc2286

  const ripemd128keys = [
    "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B",
    "4A656665",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "0102030405060708090A0B0C0D0E0F10111213141516171819",
    "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C",
    """AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA""",
    """AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"""
  ]

  const ripemd160keys = [
    "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B",
    "4A656665",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "0102030405060708090A0B0C0D0E0F10111213141516171819",
    "0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C",
    """AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA""",
    """AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"""
  ]

  const ripemddata = [
    "4869205468657265",
    "7768617420646F2079612077616E7420666F72206E6F7468696E673F",
    """DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
       DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD""",
    """CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD
       CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD""",
    "546573742057697468205472756E636174696F6E",
    """54657374205573696E67204C6172676572205468616E20426C6F636B2D5369
       7A65204B6579202D2048617368204B6579204669727374""",
    """54657374205573696E67204C6172676572205468616E20426C6F636B2D5369
       7A65204B657920616E64204C6172676572205468616E204F6E6520426C6F63
       6B2D53697A652044617461"""
  ]

  const ripemd160digests = [
    "24CB4BD67D20FC1A5D2ED7732DCC39377F0A5668",
    "DDA6C0213A485A9E24F4742064A7F033B43C4069",
    "B0B105360DE759960AB4F35298E116E295D8E7C1",
    "D5CA862F4D21D5E610E18B4CF1BEB97A4365ECF4",
    "7619693978F91D90539AE786500FF3D8E0518E39",
    "6466CA07AC5EAC29E1BD523E5ADA7605B791FD8B",
    "69EA60798D71616CCE5FD0871E23754CD75D5A0A"
  ]

  const ripemd128digests = [
    "FBF61F9492AA4BBF81C172E84E0734DB", "875F828862B6B334B427C55F9F7FF09B",
    "09F0B2846D2F543DA363CBEC8D62A38D", "BDBBD7CF03E44B5AA60AF815BE4D2294",
    "E79808F24B25FD031C155F0D551D9A3A", "DC732928DE98104A1F59D373C150ACBB",
    "5C6BEC96793E16D40690C237635F30C5"
  ]

  # SHA2 224/256/384/512 test vectors
  # [https://tools.ietf.org/html/rfc4231].

  const sha2keys = [
    "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B",
    "4A656665",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "0102030405060708090A0B0C0D0E0F10111213141516171819",
    """AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       AAAAAA""",
    """AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       AAAAAA"""
  ]

  const sha2data = [
    "4869205468657265",
    "7768617420646F2079612077616E7420666F72206E6F7468696E673F",
    """DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
       DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD""",
    """CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD
       CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD""",
    """54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A
       65204B6579202D2048617368204B6579204669727374""",
    """5468697320697320612074657374207573696E672061206C6172676572207468
       616E20626C6F636B2D73697A65206B657920616E642061206C61726765722074
       68616E20626C6F636B2D73697A6520646174612E20546865206B6579206E6565
       647320746F20626520686173686564206265666F7265206265696E6720757365
       642062792074686520484D414320616C676F726974686D2E"""
  ]

  const sha224digests = [
    "896FB1128ABBDF196832107CD49DF33F47B4B1169912BA4F53684B22",
    "A30E01098BC6DBBF45690F3A7E9E6D0F8BBEA2A39E6148008FD05E44",
    "7FB3CB3588C6C1F6FFA9694D7D6AD2649365B0C1F65D69D1EC8333EA",
    "6C11506874013CAC6A2ABC1BB382627CEC6A90D86EFC012DE7AFEC5A",
    "95E9A0DB962095ADAEBE9B2D6F0DBCE2D499F112F2D2B7273FA6870E",
    "3A854166AC5D9F023F54D517D0B39DBD946770DB9C2B95C9F6F565D1"
  ]

  const sha256digests = [
    "B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7",
    "5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843",
    "773EA91E36800E46854DB8EBD09181A72959098B3EF8C122D9635514CED565FE",
    "82558A389A443C0EA4CC819899F2083A85F0FAA3E578F8077A2E3FF46729665B",
    "60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5140546040F0EE37F54",
    "9B09FFA71B942FCB27635FBCD5B0E944BFDC63644F0713938A7F51535C3A35E2"
  ]

  const sha384digests = [
    """AFD03944D84895626B0825F4AB46907F15F9DADBE4101EC682AA034C7CEBC59C
       FAEA9EA9076EDE7F4AF152E8B2FA9CB6""",
    """AF45D2E376484031617F78D2B58A6B1B9C7EF464F5A01B47E42EC3736322445E
       8E2240CA5E69E2C78B3239ECFAB21649""",
    """88062608D3E6AD8A0AA2ACE014C8A86F0AA635D947AC9FEBE83EF4E55966144B
       2A5AB39DC13814B94E3AB6E101A34F27""",
    """3E8A69B7783C25851933AB6290AF6CA77A9981480850009CC5577C6E1F573B4E
       6801DD23C4A7D679CCF8A386C674CFFB""",
    """4ECE084485813E9088D2C63A041BC5B44F9EF1012A2B588F3CD11F05033AC4C6
       0C2EF6AB4030FE8296248DF163F44952""",
    """6617178E941F020D351E2F254E8FD32C602420FEB0B8FB9ADCCEBB82461E99C5
       A678CC31E799176D3860E6110C46523E"""
  ]

  const sha512digests = [
    """87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDE
       DAA833B7D6B8A702038B274EAEA3F4E4BE9D914EEB61F1702E696C203A126854""",
    """164B7A7BFCF819E2E395FBE73B56E0A387BD64222E831FD610270CD7EA250554
       9758BF75C05A994A6D034F65F8F0E6FDCAEAB1A34D4A6B4B636E070A38BCE737""",
    """FA73B0089D56A284EFB0F0756C890BE9B1B5DBDD8EE81A3655F83E33B2279D39
       BF3E848279A722C806B485A47E67C807B946A337BEE8942674278859E13292FB""",
    """B0BA465637458C6990E5A8C5F61D4AF7E576D97FF94B872DE76F8050361EE3DB
       A91CA5C11AA25EB4D679275CC5788063A5F19741120C4F2DE2ADEBEB10A298DD""",
    """80B24263C7C1A3EBB71493C1DD7BE8B49B46D1F41B4AEEC1121B013783F8F352
       6B56D037E05F2598BD0FD2215D6A1E5295E64F73F63F0AEC8B915A985D786598""",
    """E37B6A775DC87DBAA4DFA9F96E5E3FFDDEBD71F8867289865DF5A32D20CDC944
       B6022CAC3C4982B10D5EEB55C3E4DE15134676FB6DE0446065C97440FA8C6A58"""
  ]

  # SHA3 224/256/384/512 test vectors
  # [https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values#aMsgAuth].
  # Section [MESSAGE AUTHENTICATION]

  const sha3texts = [
    "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E",
    "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E",
    "53616D706C65206D65737361676520666F72206B65796C656E3E626C6F636B6C656E",
    """53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C
       656E2C2077697468207472756E636174656420746167"""
  ]

  const sha3_224keys = [
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B",
    """000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
       202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F
       404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F
       606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F
       808182838485868788898A8B8C8D8E8F""",
    """000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
       202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F
       404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F
       606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F
       808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F
       A0A1A2A3A4A5A6A7A8A9AAAB""",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B"
  ]
  const sha3_256keys = [
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    """000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
       202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F
       404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F
       606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F
       8081828384858687""",
    """000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
       202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F
       404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F
       606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F
       808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F
       A0A1A2A3A4A5A6A7""",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
  ]
  const sha3_384keys = [
    """000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
       202122232425262728292A2B2C2D2E2F""",
    """000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
       202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F
       404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F
       6061626364656667""",
    """000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
       202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F
       404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F
       606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F
       808182838485868788898A8B8C8D8E8F9091929394959697""",
    """000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
       202122232425262728292A2B2C2D2E2F"""
  ]
  const sha3_512keys = [
    """000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
       202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F""",
    """000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
       202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F
       4041424344454647""",
    """000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
       202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F
       404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F
       606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F
       8081828384858687""",
    """000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
       202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"""
  ]
  const sha3_224digests = [
    "332CFD59347FDB8E576E77260BE4ABA2D6DC53117B3BFB52C6D18C04",
    "D8B733BCF66C644A12323D564E24DCF3FC75F231F3B67968359100C7",
    "078695EECC227C636AD31D063A15DD05A7E819A66EC6D8DE1E193E59",
    "8569C54CBB00A9B78FF1B391B0E5CD2FA5EC728550AA3979703305D4"
  ]
  const sha3_256digests = [
    "4FE8E202C4F058E8DDDC23D8C34E467343E23555E24FC2F025D598F558F67205",
    "68B94E2E538A9BE4103BEBB5AA016D47961D4D1AA906061313B557F8AF2C3FAA",
    "9BCF2C238E235C3CE88404E813BD2F3A97185AC6F238C63D6229A00B07974258",
    "C8DC7148D8C1423AA549105DAFDF9CAD2941471B5C62207088E56CCF2DD80545"
  ]
  const sha3_384digests = [
    """D588A3C51F3F2D906E8298C1199AA8FF6296218127F6B38A90B6AFE2C5617725
       BC99987F79B22A557B6520DB710B7F42""",
    """A27D24B592E8C8CBF6D4CE6FC5BF62D8FC98BF2D486640D9EB8099E24047837F
       5F3BFFBE92DCCE90B4ED5B1E7E44FA90""",
    """E5AE4C739F455279368EBF36D4F5354C95AA184C899D3870E460EBC288EF1F94
       70053F73F7C6DA2A71BCAEC38CE7D6AC""",
    """25F4BF53606E91AF79D24A4BB1FD6AECD44414A30C8EBB0AE09764C71ACEEFE8
       DFA72309E48152C98294BE658A33836E"""
  ]
  const sha3_512digests = [
    """4EFD629D6C71BF86162658F29943B1C308CE27CDFA6DB0D9C3CE81763F9CBCE5
       F7EBE9868031DB1A8F8EB7B6B95E5C5E3F657A8996C86A2F6527E307F0213196""",
    """544E257EA2A3E5EA19A590E6A24B724CE6327757723FE2751B75BF007D80F6B3
       60744BF1B7A88EA585F9765B47911976D3191CF83C039F5FFAB0D29CC9D9B6DA""",
    """5F464F5E5B7848E3885E49B2C385F0694985D0E38966242DC4A5FE3FEA4B37D4
       6B65CECED5DCF59438DD840BAB22269F0BA7FEBDB9FCF74602A35666B2A32915""",
    """7BB06D859257B25CE73CA700DF34C5CBEF5C898BAC91029E0B27975D4E526A08
       8F5E590EE736969F445643A58BEE7EE0CBBBB2E14775584435D36AD0DE6B9499"""
  ]

  test "HMAC block sizes":
    var ctx1: HMAC[sha224]
    var ctx2: HMAC[sha256]
    var ctx3: HMAC[sha384]
    var ctx4: HMAC[sha512]
    var ctx5: HMAC[ripemd128]
    var ctx6: HMAC[ripemd160]
    var ctx7: HMAC[sha3_224]
    var ctx8: HMAC[sha3_256]
    var ctx9: HMAC[sha3_384]
    var ctx0: HMAC[sha3_512]
    var ctxA: HMAC[sha1]
    check:
      ctx1.sizeBlock == 64'u
      ctx2.sizeBlock == 64'u
      ctx3.sizeBlock == 128'u
      ctx4.sizeBlock == 128'u
      ctx5.sizeBlock == 64'u
      ctx6.sizeBlock == 64'u
      ctx7.sizeBlock == 144'u
      ctx8.sizeBlock == 136'u
      ctx9.sizeBlock == 104'u
      ctx0.sizeBlock == 72'u
      ctxA.sizeBlock == 64'u

  test "HMAC digest sizes":
    var ctx1: HMAC[sha224]
    var ctx2: HMAC[sha256]
    var ctx3: HMAC[sha384]
    var ctx4: HMAC[sha512]
    var ctx5: HMAC[ripemd128]
    var ctx6: HMAC[ripemd160]
    var ctx7: HMAC[sha3_224]
    var ctx8: HMAC[sha3_256]
    var ctx9: HMAC[sha3_384]
    var ctx0: HMAC[sha3_512]
    var ctxA: HMAC[sha1]
    check:
      ctx1.sizeDigest == uint(sha224.sizeDigest)
      ctx2.sizeDigest == uint(sha256.sizeDigest)
      ctx3.sizeDigest == uint(sha384.sizeDigest)
      ctx4.sizeDigest == uint(sha512.sizeDigest)
      ctx5.sizeDigest == uint(ripemd128.sizeDigest)
      ctx6.sizeDigest == uint(ripemd160.sizeDigest)
      ctx7.sizeDigest == uint(sha3_224.sizeDigest)
      ctx8.sizeDigest == uint(sha3_256.sizeDigest)
      ctx9.sizeDigest == uint(sha3_384.sizeDigest)
      ctx0.sizeDigest == uint(sha3_512.sizeDigest)
      ctxA.sizeDigest == uint(sha1.sizeDigest)

  test "HMAC-SHA1 test vectors":
    for i in 0..<len(sha1digests):
      var key = fromHex(stripSpaces(sha1keys[i]))
      var data = fromHex(stripSpaces(sha1data[i]))
      var ctx: HMAC[sha1]
      ctx.init(cast[ptr byte](addr key[0]), uint(len(key)))
      ctx.update(cast[ptr byte](addr data[0]), uint(len(data)))
      var digest1 = $ctx.finish()
      ctx.init(key)
      ctx.update(data)
      var digest5 = $ctx.finish()
      var digest2 = $sha1.hmac(
        cast[ptr byte](addr key[0]), uint(len(key)),
        cast[ptr byte](addr data[0]), uint(len(data))
      )
      var digest3 = $sha1.hmac(key, data)
      ctx.clear()
      check:
        digest1 == sha1digests[i]
        digest2 == sha1digests[i]
        digest3 == sha1digests[i]
        digest5 == sha1digests[i]
        ctx.isFullZero() == true

  test "HMAC-SHA1 compile-time test vectors":
    const
      check0 = sha1.hmac(fromHex(stripSpaces(sha1keys[0])),
                         fromHex(stripSpaces(sha1data[0])))
      check1 = sha1.hmac(fromHex(stripSpaces(sha1keys[1])),
                         fromHex(stripSpaces(sha1data[1])))
      check2 = sha1.hmac(fromHex(stripSpaces(sha1keys[2])),
                         fromHex(stripSpaces(sha1data[2])))
    check:
      $check0 == sha1digests[0]
      $check1 == sha1digests[1]
      $check2 == sha1digests[2]

  test "HMAC-RIPEMD-128 test vectors":
    for i in 0..(len(ripemd128digests) - 1):
      var key = fromHex(stripSpaces(ripemd128keys[i]))
      var data = fromHex(stripSpaces(ripemddata[i]))
      var ctx: HMAC[ripemd128]
      ctx.init(cast[ptr uint8](addr key[0]), uint(len(key)))
      ctx.update(cast[ptr uint8](addr data[0]), uint(len(data)))
      var digest1 = $ctx.finish()
      ctx.init(key)
      ctx.update(data)
      var digest5 = $ctx.finish()
      var digest2 = $ripemd128.hmac(
        cast[ptr uint8](addr key[0]), uint(len(key)),
        cast[ptr uint8](addr data[0]), uint(len(data))
      )
      var digest3 = $ripemd128.hmac(key, data)
      ctx.clear()
      check:
        digest1 == ripemd128digests[i]
        digest2 == ripemd128digests[i]
        digest3 == ripemd128digests[i]
        digest5 == ripemd128digests[i]
        ctx.isFullZero() == true

  test "HMAC-RIPEMD-128 compile-time test vectors":
    const
      check0 = ripemd128.hmac(fromHex(stripSpaces(ripemd128keys[0])),
                         fromHex(stripSpaces(ripemddata[0])))
      check1 = ripemd128.hmac(fromHex(stripSpaces(ripemd128keys[1])),
                         fromHex(stripSpaces(ripemddata[1])))
      check2 = ripemd128.hmac(fromHex(stripSpaces(ripemd128keys[2])),
                         fromHex(stripSpaces(ripemddata[2])))
      check3 = ripemd128.hmac(fromHex(stripSpaces(ripemd128keys[3])),
                         fromHex(stripSpaces(ripemddata[3])))
      check4 = ripemd128.hmac(fromHex(stripSpaces(ripemd128keys[4])),
                         fromHex(stripSpaces(ripemddata[4])))
      check5 = ripemd128.hmac(fromHex(stripSpaces(ripemd128keys[5])),
                         fromHex(stripSpaces(ripemddata[5])))
      check6 = ripemd128.hmac(fromHex(stripSpaces(ripemd128keys[6])),
                         fromHex(stripSpaces(ripemddata[6])))
    check:
      $check0 == ripemd128digests[0]
      $check1 == ripemd128digests[1]
      $check2 == ripemd128digests[2]
      $check3 == ripemd128digests[3]
      $check4 == ripemd128digests[4]
      $check5 == ripemd128digests[5]
      $check6 == ripemd128digests[6]

  test "HMAC-RIPEMD-160 test vectors":
    for i in 0..(len(ripemd160digests) - 1):
      var key = fromHex(stripSpaces(ripemd160keys[i]))
      var data = fromHex(stripSpaces(ripemddata[i]))
      var ctx: HMAC[ripemd160]
      ctx.init(cast[ptr uint8](addr key[0]), uint(len(key)))
      ctx.update(cast[ptr uint8](addr data[0]), uint(len(data)))
      var digest1 = $ctx.finish()
      ctx.init(key)
      ctx.update(data)
      var digest5 = $ctx.finish()
      var digest2 = $ripemd160.hmac(
        cast[ptr uint8](addr key[0]), uint(len(key)),
        cast[ptr uint8](addr data[0]), uint(len(data))
      )
      var digest3 = $ripemd160.hmac(key, data)
      ctx.clear()
      check:
        digest1 == ripemd160digests[i]
        digest2 == ripemd160digests[i]
        digest3 == ripemd160digests[i]
        digest5 == ripemd160digests[i]
        ctx.isFullZero() == true

  test "HMAC-RIPEMD-160 compile-time test vectors":
    const
      check0 = ripemd160.hmac(fromHex(stripSpaces(ripemd160keys[0])),
                         fromHex(stripSpaces(ripemddata[0])))
      check1 = ripemd160.hmac(fromHex(stripSpaces(ripemd160keys[1])),
                         fromHex(stripSpaces(ripemddata[1])))
      check2 = ripemd160.hmac(fromHex(stripSpaces(ripemd160keys[2])),
                         fromHex(stripSpaces(ripemddata[2])))
      check3 = ripemd160.hmac(fromHex(stripSpaces(ripemd160keys[3])),
                         fromHex(stripSpaces(ripemddata[3])))
      check4 = ripemd160.hmac(fromHex(stripSpaces(ripemd160keys[4])),
                         fromHex(stripSpaces(ripemddata[4])))
      check5 = ripemd160.hmac(fromHex(stripSpaces(ripemd160keys[5])),
                         fromHex(stripSpaces(ripemddata[5])))
      check6 = ripemd160.hmac(fromHex(stripSpaces(ripemd160keys[6])),
                         fromHex(stripSpaces(ripemddata[6])))
    check:
      $check0 == ripemd160digests[0]
      $check1 == ripemd160digests[1]
      $check2 == ripemd160digests[2]
      $check3 == ripemd160digests[3]
      $check4 == ripemd160digests[4]
      $check5 == ripemd160digests[5]
      $check6 == ripemd160digests[6]

  test "HMAC-SHA2-224 test vectors":
    var ctx224: HMAC[sha224]
    for i in 0..(len(sha2keys) - 1):
      var key = fromHex(stripSpaces(sha2keys[i]))
      var data = fromHex(stripSpaces(sha2data[i]))
      var digest = stripSpaces(sha224digests[i])
      ctx224.init(cast[ptr uint8](addr key[0]), uint(len(key)))
      ctx224.update(cast[ptr uint8](addr data[0]), uint(len(data)))
      var check1 = $ctx224.finish()
      ctx224.init(key)
      ctx224.update(data)
      var check5 = $ctx224.finish()
      var check2 = $sha224.hmac(
        cast[ptr uint8](addr key[0]), uint(len(key)),
        cast[ptr uint8](addr data[0]), uint(len(data))
      )
      var check3 = $sha224.hmac(key, data)
      ctx224.clear()
      check:
        check1 == digest
        check2 == digest
        check3 == digest
        check5 == digest
        ctx224.isFullZero() == true

  test "HMAC-SHA2-224 compile-time test vectors":
    const
      check0 = sha224.hmac(fromHex(stripSpaces(sha2keys[0])),
                           fromHex(stripSpaces(sha2data[0])))
      check1 = sha224.hmac(fromHex(stripSpaces(sha2keys[1])),
                           fromHex(stripSpaces(sha2data[1])))
      check2 = sha224.hmac(fromHex(stripSpaces(sha2keys[2])),
                           fromHex(stripSpaces(sha2data[2])))
      check3 = sha224.hmac(fromHex(stripSpaces(sha2keys[3])),
                           fromHex(stripSpaces(sha2data[3])))
      check4 = sha224.hmac(fromHex(stripSpaces(sha2keys[4])),
                           fromHex(stripSpaces(sha2data[4])))
    check:
      $check0 == sha224digests[0]
      $check1 == sha224digests[1]
      $check2 == sha224digests[2]
      $check3 == sha224digests[3]
      $check4 == sha224digests[4]

  test "HMAC-SHA2-256 test vectors":
    var ctx256: HMAC[sha256]
    for i in 0..(len(sha2keys) - 1):
      var key = fromHex(stripSpaces(sha2keys[i]))
      var data = fromHex(stripSpaces(sha2data[i]))
      var digest = stripSpaces(sha256digests[i])
      ctx256.init(cast[ptr uint8](addr key[0]), uint(len(key)))
      ctx256.update(cast[ptr uint8](addr data[0]), uint(len(data)))
      var check1 = $ctx256.finish()
      ctx256.init(key)
      ctx256.update(data)
      var check5 = $ctx256.finish()
      var check2 = $sha256.hmac(
        cast[ptr uint8](addr key[0]), uint(len(key)),
        cast[ptr uint8](addr data[0]), uint(len(data))
      )
      var check3 = $sha256.hmac(key, data)
      ctx256.clear()
      check:
        check1 == digest
        check2 == digest
        check3 == digest
        check5 == digest
        ctx256.isFullZero() == true

  test "HMAC-SHA2-256 compile-time test vectors":
    const
      check0 = sha256.hmac(fromHex(stripSpaces(sha2keys[0])),
                           fromHex(stripSpaces(sha2data[0])))
      check1 = sha256.hmac(fromHex(stripSpaces(sha2keys[1])),
                           fromHex(stripSpaces(sha2data[1])))
      check2 = sha256.hmac(fromHex(stripSpaces(sha2keys[2])),
                           fromHex(stripSpaces(sha2data[2])))
      check3 = sha256.hmac(fromHex(stripSpaces(sha2keys[3])),
                           fromHex(stripSpaces(sha2data[3])))
      check4 = sha256.hmac(fromHex(stripSpaces(sha2keys[4])),
                           fromHex(stripSpaces(sha2data[4])))
    check:
      $check0 == sha256digests[0]
      $check1 == sha256digests[1]
      $check2 == sha256digests[2]
      $check3 == sha256digests[3]
      $check4 == sha256digests[4]

  test "HMAC-SHA2-384 test vectors":
    var ctx384: HMAC[sha384]
    for i in 0..(len(sha2keys) - 1):
      var key = fromHex(stripSpaces(sha2keys[i]))
      var data = fromHex(stripSpaces(sha2data[i]))
      var digest = stripSpaces(sha384digests[i])
      ctx384.init(cast[ptr uint8](addr key[0]), uint(len(key)))
      ctx384.update(cast[ptr uint8](addr data[0]), uint(len(data)))
      var check1 = $ctx384.finish()
      ctx384.init(key)
      ctx384.update(data)
      var check5 = $ctx384.finish()
      var check2 = $sha384.hmac(
        cast[ptr uint8](addr key[0]), uint(len(key)),
        cast[ptr uint8](addr data[0]), uint(len(data))
      )
      var check3 = $sha384.hmac(key, data)
      ctx384.clear()
      check:
        check1 == digest
        check2 == digest
        check3 == digest
        check5 == digest
        ctx384.isFullZero() == true

  test "HMAC-SHA2-384 compile-time test vectors":
    const
      check0 = sha384.hmac(fromHex(stripSpaces(sha2keys[0])),
                           fromHex(stripSpaces(sha2data[0])))
      check1 = sha384.hmac(fromHex(stripSpaces(sha2keys[1])),
                           fromHex(stripSpaces(sha2data[1])))
      check2 = sha384.hmac(fromHex(stripSpaces(sha2keys[2])),
                           fromHex(stripSpaces(sha2data[2])))
      check3 = sha384.hmac(fromHex(stripSpaces(sha2keys[3])),
                           fromHex(stripSpaces(sha2data[3])))
      check4 = sha384.hmac(fromHex(stripSpaces(sha2keys[4])),
                           fromHex(stripSpaces(sha2data[4])))
    check:
      $check0 == stripSpaces(sha384digests[0])
      $check1 == stripSpaces(sha384digests[1])
      $check2 == stripSpaces(sha384digests[2])
      $check3 == stripSpaces(sha384digests[3])
      $check4 == stripSpaces(sha384digests[4])

  test "HMAC-SHA2-512 test vectors":
    var ctx512: HMAC[sha512]
    for i in 0..(len(sha2keys) - 1):
      var key = fromHex(stripSpaces(sha2keys[i]))
      var data = fromHex(stripSpaces(sha2data[i]))
      var digest = stripSpaces(sha512digests[i])
      ctx512.init(cast[ptr uint8](addr key[0]), uint(len(key)))
      ctx512.update(cast[ptr uint8](addr data[0]), uint(len(data)))
      var check1 = $ctx512.finish()
      ctx512.init(key)
      ctx512.update(data)
      var check5 = $ctx512.finish()
      var check2 = $sha512.hmac(
        cast[ptr uint8](addr key[0]), uint(len(key)),
        cast[ptr uint8](addr data[0]), uint(len(data))
      )
      var check3 = $sha512.hmac(key, data)
      ctx512.clear()
      check:
        check1 == digest
        check2 == digest
        check3 == digest
        check5 == digest
        ctx512.isFullZero() == true

  test "HMAC-SHA2-512 compile-time test vectors":
    const
      check0 = sha512.hmac(fromHex(stripSpaces(sha2keys[0])),
                           fromHex(stripSpaces(sha2data[0])))
      check1 = sha512.hmac(fromHex(stripSpaces(sha2keys[1])),
                           fromHex(stripSpaces(sha2data[1])))
      check2 = sha512.hmac(fromHex(stripSpaces(sha2keys[2])),
                           fromHex(stripSpaces(sha2data[2])))
      check3 = sha512.hmac(fromHex(stripSpaces(sha2keys[3])),
                           fromHex(stripSpaces(sha2data[3])))
      check4 = sha512.hmac(fromHex(stripSpaces(sha2keys[4])),
                           fromHex(stripSpaces(sha2data[4])))
    check:
      $check0 == stripSpaces(sha512digests[0])
      $check1 == stripSpaces(sha512digests[1])
      $check2 == stripSpaces(sha512digests[2])
      $check3 == stripSpaces(sha512digests[3])
      $check4 == stripSpaces(sha512digests[4])

  test "HMAC-SHA3-224 test vectors":
    var ctx: HMAC[sha3_224]
    for i in 0..(len(sha3texts) - 1):
      var key = fromHex(stripSpaces(sha3_224keys[i]))
      var data = fromHex(stripSpaces(sha3texts[i]))
      var digest = stripSpaces(sha3_224digests[i])
      ctx.init(cast[ptr uint8](addr key[0]), uint(len(key)))
      ctx.update(cast[ptr uint8](addr data[0]), uint(len(data)))
      var check1 = $ctx.finish()
      ctx.init(key)
      ctx.update(data)
      var check5 = $ctx.finish()
      var check2 = $sha3_224.hmac(
        cast[ptr uint8](addr key[0]), uint(len(key)),
        cast[ptr uint8](addr data[0]), uint(len(data))
      )
      var check3 = $sha3_224.hmac(key, data)
      ctx.clear()
      check:
        check1 == digest
        check2 == digest
        check3 == digest
        check5 == digest
        ctx.isFullZero() == true

  test "HMAC-SHA3-224 compile-time test vectors":
    const
      check0 = sha3_224.hmac(fromHex(stripSpaces(sha3_224keys[0])),
                             fromHex(stripSpaces(sha3texts[0])))
      check1 = sha3_224.hmac(fromHex(stripSpaces(sha3_224keys[1])),
                             fromHex(stripSpaces(sha3texts[1])))
      check2 = sha3_224.hmac(fromHex(stripSpaces(sha3_224keys[2])),
                             fromHex(stripSpaces(sha3texts[2])))
      check3 = sha3_224.hmac(fromHex(stripSpaces(sha3_224keys[3])),
                             fromHex(stripSpaces(sha3texts[3])))
    check:
      $check0 == stripSpaces(sha3_224digests[0])
      $check1 == stripSpaces(sha3_224digests[1])
      $check2 == stripSpaces(sha3_224digests[2])
      $check3 == stripSpaces(sha3_224digests[3])

  test "HMAC-SHA3-256 test vectors":
    var ctx: HMAC[sha3_256]
    for i in 0..(len(sha3texts) - 1):
      var key = fromHex(stripSpaces(sha3_256keys[i]))
      var data = fromHex(stripSpaces(sha3texts[i]))
      var digest = stripSpaces(sha3_256digests[i])
      ctx.init(cast[ptr uint8](addr key[0]), uint(len(key)))
      ctx.update(cast[ptr uint8](addr data[0]), uint(len(data)))
      var check1 = $ctx.finish()
      ctx.init(key)
      ctx.update(data)
      var check5 = $ctx.finish()
      var check2 = $sha3_256.hmac(
        cast[ptr uint8](addr key[0]), uint(len(key)),
        cast[ptr uint8](addr data[0]), uint(len(data))
      )
      var check3 = $sha3_256.hmac(key, data)
      ctx.clear()
      check:
        check1 == digest
        check2 == digest
        check3 == digest
        check5 == digest
        ctx.isFullZero() == true

  test "HMAC-SHA3-256 compile-time test vectors":
    const
      check0 = sha3_256.hmac(fromHex(stripSpaces(sha3_256keys[0])),
                             fromHex(stripSpaces(sha3texts[0])))
      check1 = sha3_256.hmac(fromHex(stripSpaces(sha3_256keys[1])),
                             fromHex(stripSpaces(sha3texts[1])))
      check2 = sha3_256.hmac(fromHex(stripSpaces(sha3_256keys[2])),
                             fromHex(stripSpaces(sha3texts[2])))
      check3 = sha3_256.hmac(fromHex(stripSpaces(sha3_256keys[3])),
                             fromHex(stripSpaces(sha3texts[3])))
    check:
      $check0 == stripSpaces(sha3_256digests[0])
      $check1 == stripSpaces(sha3_256digests[1])
      $check2 == stripSpaces(sha3_256digests[2])
      $check3 == stripSpaces(sha3_256digests[3])

  test "HMAC-SHA3-384 test vectors":
    var ctx: HMAC[sha3_384]
    for i in 0..(len(sha3texts) - 1):
      var key = fromHex(stripSpaces(sha3_384keys[i]))
      var data = fromHex(stripSpaces(sha3texts[i]))
      var digest = stripSpaces(sha3_384digests[i])
      ctx.init(cast[ptr uint8](addr key[0]), uint(len(key)))
      ctx.update(cast[ptr uint8](addr data[0]), uint(len(data)))
      var check1 = $ctx.finish()
      ctx.init(key)
      ctx.update(data)
      var check5 = $ctx.finish()
      var check2 = $sha3_384.hmac(
        cast[ptr uint8](addr key[0]), uint(len(key)),
        cast[ptr uint8](addr data[0]), uint(len(data))
      )
      var check3 = $sha3_384.hmac(key, data)
      ctx.clear()
      check:
        check1 == digest
        check2 == digest
        check3 == digest
        check5 == digest
        ctx.isFullZero() == true

  test "HMAC-SHA3-384 compile-time test vectors":
    const
      check0 = sha3_384.hmac(fromHex(stripSpaces(sha3_384keys[0])),
                             fromHex(stripSpaces(sha3texts[0])))
      check1 = sha3_384.hmac(fromHex(stripSpaces(sha3_384keys[1])),
                             fromHex(stripSpaces(sha3texts[1])))
      check2 = sha3_384.hmac(fromHex(stripSpaces(sha3_384keys[2])),
                             fromHex(stripSpaces(sha3texts[2])))
      check3 = sha3_384.hmac(fromHex(stripSpaces(sha3_384keys[3])),
                             fromHex(stripSpaces(sha3texts[3])))
    check:
      $check0 == stripSpaces(sha3_384digests[0])
      $check1 == stripSpaces(sha3_384digests[1])
      $check2 == stripSpaces(sha3_384digests[2])
      $check3 == stripSpaces(sha3_384digests[3])

  test "HMAC-SHA3-512 test vectors":
    var ctx: HMAC[sha3_512]
    for i in 0..(len(sha3texts) - 1):
      var key = fromHex(stripSpaces(sha3_512keys[i]))
      var data = fromHex(stripSpaces(sha3texts[i]))
      var digest = stripSpaces(sha3_512digests[i])
      ctx.init(cast[ptr uint8](addr key[0]), uint(len(key)))
      ctx.update(cast[ptr uint8](addr data[0]), uint(len(data)))
      var check1 = $ctx.finish()
      ctx.init(key)
      ctx.update(data)
      var check5 = $ctx.finish()
      var check2 = $sha3_512.hmac(
        cast[ptr uint8](addr key[0]), uint(len(key)),
        cast[ptr uint8](addr data[0]), uint(len(data))
      )
      var check3 = $sha3_512.hmac(key, data)
      ctx.clear()
      check:
        check1 == digest
        check2 == digest
        check3 == digest
        check5 == digest
        ctx.isFullZero() == true

  test "HMAC-SHA3-512 compile-time test vectors":
    const
      check0 = sha3_512.hmac(fromHex(stripSpaces(sha3_512keys[0])),
                             fromHex(stripSpaces(sha3texts[0])))
      check1 = sha3_512.hmac(fromHex(stripSpaces(sha3_512keys[1])),
                             fromHex(stripSpaces(sha3texts[1])))
      check2 = sha3_512.hmac(fromHex(stripSpaces(sha3_512keys[2])),
                             fromHex(stripSpaces(sha3texts[2])))
      check3 = sha3_512.hmac(fromHex(stripSpaces(sha3_512keys[3])),
                             fromHex(stripSpaces(sha3texts[3])))
    check:
      $check0 == stripSpaces(sha3_512digests[0])
      $check1 == stripSpaces(sha3_512digests[1])
      $check2 == stripSpaces(sha3_512digests[2])
      $check3 == stripSpaces(sha3_512digests[3])

  test "HMAC API test":
    var stringToHmac = "Hello World!"
    var stringHmacKey = "AliceKey"
    let ptrToHmac = cast[ptr byte](addr stringToHmac[0])
    let ptrHmacKey = cast[ptr byte](addr stringHmacKey[0])
    let toHmacLen = uint(len(stringToHmac))
    let hmacKeyLen = uint(len(stringHmacKey))
    var hctx1, hctx2: HMAC[sha256]
    hctx1.init(stringHmacKey)
    hctx2.init(ptrHmacKey, hmacKeyLen)
    hctx1.update(stringToHmac)
    hctx1.update(stringToHmac)
    hctx2.update(ptrToHmac, toHmacLen)
    hctx2.update(ptrToHmac, toHmacLen)
    var md1 = hctx1.finish()
    var md2 = hctx2.finish()
    hctx1.reset()
    hctx2.reset()
    hctx1.update(stringToHmac)
    hctx1.update(stringToHmac)
    hctx2.update(ptrToHmac, toHmacLen)
    hctx2.update(ptrToHmac, toHmacLen)
    var md3 = hctx1.finish()
    var md4 = hctx2.finish()
    hctx1.clear()
    hctx2.clear()
    var md5 = sha256.hmac(stringHmacKey, stringToHmac & stringToHmac)
    check:
      $md1 == $md1
      $md1 == $md2
      $md1 == $md3
      $md1 == $md4
      $md1 == $md5
      md1 == md1
      md1 == md2
      md1 == md3
      md1 == md4
      md1 == md5
      hctx1.isFullZero() == true
      hctx2.isFullZero() == true
