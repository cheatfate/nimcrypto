import nimcrypto/utils, nimcrypto/bcmode, nimcrypto/rijndael
import unittest

when defined(nimHasUsed): {.used.}

suite "Block cipher modes Tests":

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
    # GCM test vectors
    gcm128Keys = [
      "00000000000000000000000000000000", "00000000000000000000000000000000",
      "FEFFE9928665731C6D6A8F9467308308", "FEFFE9928665731C6D6A8F9467308308",
      "FEFFE9928665731C6D6A8F9467308308", "FEFFE9928665731C6D6A8F9467308308",
      "00000000000000000000000000000000", "00000000000000000000000000000000",
      "00000000000000000000000000000000", "00000000000000000000000000000000",
      "00000000000000000000000000000000", "00000000000000000000000000000000",
      "843FFCF5D2B72694D19ED01D01249412"
    ]
    gcm192Keys = [
      "000000000000000000000000000000000000000000000000",
      "000000000000000000000000000000000000000000000000",
      "FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C",
      "FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C",
      "FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C",
      "FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C",
    ]
    gcm256Keys = [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308",
      "FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308",
      "FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308",
      "FEFFE9928665731C6D6A8F9467308308FEFFE9928665731C6D6A8F9467308308",
    ]
    gcmIvs = [
      "000000000000000000000000", "000000000000000000000000",
      "CAFEBABEFACEDBADDECAF888", "CAFEBABEFACEDBADDECAF888",
      "CAFEBABEFACEDBAD",
      """9313225DF88406E555909C5AFF5269AA6A7A9538534F7DA1E4C303D2A318A728
         C3C0C95156809539FCF0E2429A6B525416AEDBF5A0DE6A57A637B39B""",
      "000000000000000000000000", "000000000000000000000000",
      "000000000000000000000000", "000000000000000000000000",
      """FFFFFFFF00000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000""",
      """FFFFFFFF00000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000""",
      "DBCCA32EBF9B804617C3AA9E"
    ]
    gcmP = [
      "", "00000000000000000000000000000000",
      """D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A72
         1C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255""",
      """D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A72
         1C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39""",
      """D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A72
         1C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39""",
      """D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A72
         1C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39""",
      "",
      """0000000000000000000000000000000000000000000000000000000000000000
         00000000000000000000000000000000""",
      """0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000
         00000000000000000000000000000000""",
      """0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000""",
      """0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000""",
      """0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000
         0000000000000000000000000000000000000000000000000000000000000000""",
      """000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
         202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F
         404142434445464748494A4B4C4D4E4F"""
    ]
    gcm128E = [
      "", "0388DACE60B6A392F328C2B971B2FE78",
      """42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E
         21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091473F5985""",
      """42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E
         21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E091""",
      """61353B4C2806934A777FF51FA22A4755699B2A714FCDC6F83766E5F97B6C7423
         73806900E49F24B22B097544D4896B424989B5E1EBAC0F07C23F4598""",
      """8CE24998625615B603A033ACA13FB894BE9112A5C3A211A8BA262A3CCA7E2CA7
         01E4A9A4FBA43C90CCDCB281D48C7C6FD62875D2ACA417034C34AEE5""",
      "",
      """0388DACE60B6A392F328C2B971B2FE78F795AAAB494B5923F7FD89FF948BC1E0
         200211214E7394DA2089B6ACD093ABE0""",
      """0388DACE60B6A392F328C2B971B2FE78F795AAAB494B5923F7FD89FF948BC1E0
         200211214E7394DA2089B6ACD093ABE0C94DA219118E297D7B7EBCBCC9C388F2
         8ADE7D85A8EE35616F7124A9D5270291""",
      """0388DACE60B6A392F328C2B971B2FE78F795AAAB494B5923F7FD89FF948BC1E0
         200211214E7394DA2089B6ACD093ABE0C94DA219118E297D7B7EBCBCC9C388F2
         8ADE7D85A8EE35616F7124A9D527029195B84D1B96C690FF2F2DE30BF2EC89E0
         0253786E126504F0DAB90C48A30321DE3345E6B0461E7C9E6C6B7AFEDDE83F40""",
      """56B3373CA9EF6E4A2B64FE1E9A17B61425F10D47A75A5FCE13EFC6BC784AF24F
         4141BDD48CF7C770887AFD573CCA5418A9AEFFCD7C5CEDDFC6A78397B9A85B49
         9DA558257267CAAB2AD0B23CA476A53CB17FB41C4B8B475CB4F3F7165094C229
         C9E8C4DC0A2A5FF1903E501511221376A1CDB8364C5061A20CAE74BC4ACD76CE
         B0ABC9FD3217EF9F8C90BE402DDF6D8697F4F880DFF15BFB7A6B28241EC8FE18
         3C2D59E3F9DFFF653C7126F0ACB9E64211F42BAE12AF462B1070BEF1AB5E3606""",
      """56B3373CA9EF6E4A2B64FE1E9A17B61425F10D47A75A5FCE13EFC6BC784AF24F
         4141BDD48CF7C770887AFD573CCA5418A9AEFFCD7C5CEDDFC6A78397B9A85B49
         9DA558257267CAAB2AD0B23CA476A53CB17FB41C4B8B475CB4F3F7165094C229
         C9E8C4DC0A2A5FF1903E501511221376A1CDB8364C5061A20CAE74BC4ACD76CE
         B0ABC9FD3217EF9F8C90BE402DDF6D8697F4F880DFF15BFB7A6B28241EC8FE18
         3C2D59E3F9DFFF653C7126F0ACB9E64211F42BAE12AF462B1070BEF1AB5E3606
         872CA10DEE15B3249B1A1B958F23134C4BCCB7D03200BCE420A2F8EB66DCF364
         4D1423C1B5699003C13ECEF4BF38A3B60EEDC34033BAC1902783DC6D89E2E774
         188A439C7EBCC0672DBDA4DDCFB2794613B0BE41315EF778708A70EE7D75165C""",
      """6268C6FA2A80B2D137467F092F657AC04D89BE2BEAA623D61B5A868C8F03FF95
         D3DCEE23AD2F1AB3A6C80EAF4B140EB05DE3457F0FBC111A6B43D0763AA422A3
         013CF1DC37FE417D1FBFC449B75D4CC5"""

    ]
    gcm192E = [
      "", "98E7247C07F0FE411C267E4384B0F600",
      """3980CA0B3C00E841EB06FAC4872A2757859E1CEAA6EFD984628593B40CA1E19C
         7D773D00C144C525AC619D18C84A3F4718E2448B2FE324D9CCDA2710ACADE256""",
      """3980CA0B3C00E841EB06FAC4872A2757859E1CEAA6EFD984628593B40CA1E19C
         7D773D00C144C525AC619D18C84A3F4718E2448B2FE324D9CCDA2710""",
      """0F10F599AE14A154ED24B36E25324DB8C566632EF2BBB34F8347280FC4507057
         FDDC29DF9A471F75C66541D4D4DAD1C9E93A19A58E8B473FA0F062F7""",
      """D27E88681CE3243C4830165A8FDCF9FF1DE9A1D8E6B447EF6EF7B79828666E45
         81E79012AF34DDD9E2F037589B292DB3E67C036745FA22E7E9B7373B"""
    ]
    gcm256E = [
      "", "CEA7403D4D606B6E074EC5D3BAF39D18",
      """522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA
         8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F662898015AD""",
      """522DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA
         8CB08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F662""",
      """C3762DF1CA787D32AE47C13BF19844CBAF1AE14D0B976AFAC52FF7D79BBA9DE0
         FEB582D33934A4F0954CC2363BC73F7862AC430E64ABE499F47C9B1F""",
      """5A8DEF2F0C9E53F1F75D7853659E2A20EEB2B22AAFDE6419A058AB4F6F746BF4
         0FC0C3B780F244452DA3EBF1C5D82CDEA2418997200EF82E44AE7E3F"""
    ]
    gcmAads = [
      "", "", "", "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2",
      "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2",
      "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2",
      """D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721
         C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD25552
         2DC1F099567D07F47F37A32A84427D643A8CDCBFE5C0C97598A2BD2555D1AA8CB
         08E48590DBB3DA7B08B1056828838C5F61E6393BA7A0ABCC9F662898015AD""",
      "", "", "", "", "",
      "00000000000000000000000000000000101112131415161718191A1B1C1D1E1F"

    ]
    gcm128Tags = [
      "58E2FCCEFA7E3061367F1D57A4E7455A", "AB6E47D42CEC13BDF53A67B21257BDDF",
      "4D5C2AF327CD64A62CF35ABD2BA6FAB4", "5BC94FBC3221A5DB94FAE95AE7121A47",
      "3612D2E79E3B0785561BE14AACA2FCCB", "619CC5AEFFFE0BFA462AF43C1699D050",
      "5FEA793A2D6F974D37E68E0CB8FF9492", "9DD0A376B08E40EB00C35F29F9EA61A4",
      "98885A3A22BD4742FE7B72172193B163", "CAC45F60E31EFD3B5A43B98A22CE1AA1",
      "566F8EF683078BFDEEFFA869D751A017", "8B307F6B33286D0AB026A9ED3FE1E85F",
      "3B629CCFBC1119B7319E1DCE2CD6FD6D"
    ]
    gcm192Tags = [
      "CD33B28AC773F74BA00ED1F312572435", "2FF58D80033927AB8EF4D4587514F0FB",
      "9924A7C8587336BFB118024DB8674A14", "2519498E80F1478F37BA55BD6D27618C",
      "65DCC57FCF623A24094FCCA40D3533F8", "DCF566FF291C25BBB8568FC3D376A6D9"
    ]
    gcm256Tags = [
      "530F8AFBC74536B9A963B4F1C4CB738B", "D0D1C8A799996BF0265B98B5D48AB919",
      "B094DAC5D93471BDEC1A502270E3CC6C", "76FC6ECE0F4E1768CDDF8853BB2D551B",
      "3A337DBF46A792C45E454913FE2EA8F2", "A44A8266EE1C8EB0C8B5D4CF5AE9F19A"
    ]

  test "AES-128/192/256-ECB/CBC/OFB/CFB/CTR/GCM block sizes":
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
    var gcm128: GCM[aes128]
    var gcm192: GCM[aes192]
    var gcm256: GCM[aes256]
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
      gcm128.sizeBlock == aes128.sizeBlock
      gcm192.sizeBlock == aes192.sizeBlock
      gcm256.sizeBlock == aes256.sizeBlock

  test "AES-128/192/256-ECB/CBC/OFB/CFB/CTR/GCM key sizes":
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
    var gcm128: GCM[aes128]
    var gcm192: GCM[aes192]
    var gcm256: GCM[aes256]
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
      gcm128.sizeKey == aes128.sizeKey
      gcm192.sizeKey == aes192.sizeKey
      gcm256.sizeKey == aes256.sizeKey

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

  test "CTR/ECB equality test":
    # This test is based on statement that ECB[T](key) = CTR[T](key, iv)
    # where IV is fullzero, and CTR counter is also zero.
    var ctx1: CTR[aes128]
    var ctx2: ECB[aes128]
    var ctx3: CTR[aes256]
    var ctx4: ECB[aes256]
    var key128: array[aes128.sizeKey, byte]
    var key256: array[aes256.sizeKey, byte]
    var iv: array[aes128.sizeBlock, byte]
    var data: array[aes128.sizeBlock, byte]
    var output1: array[aes128.sizeBlock, byte]
    var output2: array[aes128.sizeBlock, byte]
    ctx1.init(key128, iv)
    ctx2.init(key128)
    ctx3.init(key256, iv)
    ctx4.init(key256)
    ctx1.encrypt(data, output1)
    ctx2.encrypt(data, output2)
    check:
      output1 == output2
      isFullZero(output1) == false
    burnMem(output1)
    burnMem(output2)
    check:
      output1 == output2
    ctx3.encrypt(data, output1)
    ctx4.encrypt(data, output2)
    check:
      output1 == output2
      isFullZero(output1) == false

  test "AES-128-GCM test vectors":
    var ctx1: GCM[aes128]
    var ctx2: GCM[aes128]
    var key, pt, iv, aad, ptcheck, ctcheck: seq[byte]
    for i in 0..<len(gcm128Keys):
      key = fromHex(stripSpaces(gcm128Keys[i]))
      iv = fromHex(stripSpaces(gcmIvs[i]))
      if len(gcmP) > 0:
        pt = fromHex(stripSpaces(gcmP[i]))
        ptcheck = newSeq[byte](len(pt))
        ctcheck = fromHex(stripSpaces(gcm128E[i]))
      else:
        pt = newSeq[byte]()
        ptcheck = newSeq[byte]()
        ctcheck = newSeq[byte]()
      if len(gcmAads) > 0:
        aad = fromHex(stripSpaces(gcmAads[i]))
      else:
        aad = newSeq[byte]()
      ctx1.init(key, iv, aad)
      ctx2.init(key, iv, aad)
      var etagbuf = newSeq[byte](ctx1.sizeBlock)
      var dtagbuf = newSeq[byte](ctx1.sizeBlock)
      if len(pt) > 0:
        var ct = newSeq[byte](len(pt))
        ctx1.encrypt(pt, ct)
        ctx2.decrypt(ct, ptcheck)
        check:
          ct == ctcheck
          pt == ptcheck
      ctx1.getTag(etagbuf)
      ctx2.getTag(dtagbuf)
      check:
        dtagbuf == etagbuf
        etagbuf == fromHex(stripSpaces(gcm128Tags[i]))
      ctx1.clear()
      ctx2.clear()
      check:
        ctx1.isFullZero() == true
        ctx2.isFullZero() == true

  test "AES-192-GCM test vectors":
    var ctx1: GCM[aes192]
    var ctx2: GCM[aes192]
    var key, pt, iv, aad, ptcheck, ctcheck: seq[byte]
    for i in 0..<len(gcm192Keys):
      key = fromHex(stripSpaces(gcm192Keys[i]))
      iv = fromHex(stripSpaces(gcmIvs[i]))
      if len(gcmP) > 0:
        pt = fromHex(stripSpaces(gcmP[i]))
        ptcheck = newSeq[byte](len(pt))
        ctcheck = fromHex(stripSpaces(gcm192E[i]))
      else:
        pt = newSeq[byte]()
        ptcheck = newSeq[byte]()
        ctcheck = newSeq[byte]()
      if len(gcmAads) > 0:
        aad = fromHex(stripSpaces(gcmAads[i]))
      else:
        aad = newSeq[byte]()
      ctx1.init(key, iv, aad)
      ctx2.init(key, iv, aad)
      var etagbuf = newSeq[byte](ctx1.sizeBlock)
      var dtagbuf = newSeq[byte](ctx1.sizeBlock)
      if len(pt) > 0:
        var ct = newSeq[byte](len(pt))
        ctx1.encrypt(pt, ct)
        ctx2.decrypt(ct, ptcheck)
        check:
          ct == ctcheck
          pt == ptcheck
      ctx1.getTag(etagbuf)
      ctx2.getTag(dtagbuf)
      check:
        dtagbuf == etagbuf
        etagbuf == fromHex(stripSpaces(gcm192Tags[i]))
      ctx1.clear()
      ctx2.clear()
      check:
        ctx1.isFullZero() == true
        ctx2.isFullZero() == true

  test "AES-256-GCM test vectors":
    var ctx1: GCM[aes256]
    var ctx2: GCM[aes256]
    var key, pt, iv, aad, ptcheck, ctcheck: seq[byte]
    for i in 0..<len(gcm256Keys):
      key = fromHex(stripSpaces(gcm256Keys[i]))
      iv = fromHex(stripSpaces(gcmIvs[i]))
      if len(gcmP) > 0:
        pt = fromHex(stripSpaces(gcmP[i]))
        ptcheck = newSeq[byte](len(pt))
        ctcheck = fromHex(stripSpaces(gcm256E[i]))
      else:
        pt = newSeq[byte]()
        ptcheck = newSeq[byte]()
        ctcheck = newSeq[byte]()
      if len(gcmAads) > 0:
        aad = fromHex(stripSpaces(gcmAads[i]))
      else:
        aad = newSeq[byte]()
      ctx1.init(key, iv, aad)
      ctx2.init(key, iv, aad)
      var etagbuf = newSeq[byte](ctx1.sizeBlock)
      var dtagbuf = newSeq[byte](ctx1.sizeBlock)
      if len(pt) > 0:
        var ct = newSeq[byte](len(pt))
        ctx1.encrypt(pt, ct)
        ctx2.decrypt(ct, ptcheck)
        check:
          ct == ctcheck
          pt == ptcheck
      ctx1.getTag(etagbuf)
      ctx2.getTag(dtagbuf)
      check:
        dtagbuf == etagbuf
        etagbuf == fromHex(stripSpaces(gcm256Tags[i]))
      ctx1.clear()
      ctx2.clear()
      check:
        ctx1.isFullZero() == true
        ctx2.isFullZero() == true
