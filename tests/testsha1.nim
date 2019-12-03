import nimcrypto/hash, nimcrypto/sha, nimcrypto/utils
import unittest

when defined(nimHasUsed): {.used.}

suite "SHA1 Tests":

  const
    Messages = [
      "",
      "36",
      "195A",
      "DF4BD2",
      "549E959E",
      "F7FB1BE205",
      "C0E5ABEAEA63",
      "63BFC1ED7F78AB",
      "7E3D7B3EADA98866",
      "9E61E55D9ED37B1C20",
      "9777CF90DD7C7E863506",
      "4EB08C9E683C94BEA00DFA",
      "0938F2E2EBB64F8AF8BBFC91",
      "74C9996D14E87D3E6CBEA7029D",
      "51DCA5C0F8E5D49596F32D3EB874",
      "3A36EA49684820A2ADC7FC4175BA78",
      "3552694CDF663FD94B224747AC406AAF",
      "F216A1CBDE2446B1EDF41E93481D33E2ED",
      "A3CF714BF112647E727E8CFD46499ACD35A6",
      "148DE640F3C11591A6F8C5C48632C5FB79D3B7",
      "63A3CC83FD1EC1B6680E9974A0514E1A9ECEBB6A",
      "875A90909A8AFC92FB7070047E9D081EC92F3D08B8",
      "444B25F9C9259DC217772CC4478C44B6FEFF62353673",
      "487351C8A5F440E4D03386483D5FE7BB669D41ADCBFDB7",
      "46B061EF132B87F6D3B0EE2462F67D910977DA20AED13705",
      "3842B6137BB9D27F3CA5BAFE5BBB62858344FE4BA5C41589A5",
      "44D91D3D465A4111462BA0C7EC223DA6735F4F5200453CF132C3",
      "CCE73F2EABCB52F785D5A6DF63C0A105F34A91CA237FE534EE399D",
      "664E6E7946839203037A65A12174B244DE8CBC6EC3F578967A84F9CE",
      "9597F714B2E45E3399A7F02AEC44921BD78BE0FEFEE0C5E9B499488F6E",
      "75C5AD1F3CBD22E8A95FC3B089526788FB4EBCEED3E7D4443DA6E081A35E",
      "DD245BFFE6A638806667768360A95D0574E1A0BD0D18329FDB915CA484AC0D",
      "0321794B739418C24E7C2E565274791C4BE749752AD234ED56CB0A6347430C6B",
      "4C3DCF95C2F0B5258C651FCD1D51BD10425D6203067D0748D37D1340D9DDDA7DB3",
      "B8D12582D25B45290A6E1BB95DA429BEFCFDBF5B4DD41CDF3311D6988FA17CEC0723",
      "6FDA97527A662552BE15EFAEBA32A3AEA4ED449ABB5C1ED8D9BFFF544708A425D69B72",
      """09FA2792ACBB2417E8ED269041CC03C77006466E6E7AE002CF3F1AF551E8CE0BB506D7
         05""",
      """5EFA2987DA0BAF0A54D8D728792BCFA707A15798DC66743754406914D1CFE3709B
         1374EAEB""",
      """2836DE99C0F641CD55E89F5AF76638947B8227377EF88BFBA662E5682BABC1EC
         96C6992BC9A0""",
      """42143A2B9E1D0B354DF3264D08F7B602F54AAD922A3D63006D097F683DC11B90
         178423BFF2F7FE""",
      """EB60C28AD8AEDA807D69EBC87552024AD8ACA68204F1BCD29DC5A81DD228B591
         E2EFB7C4DF75EF03""",
      """7DE4BA85EC54747CDC42B1F23546B7E490E31280F066E52FAC117FD3B0792E4D
         E62D5843EE98C72015""",
      """E70653637BC5E388CCD8DC44E5EACE36F7398F2BAC993042B9BC2F4FB3B0EE7E
         23A96439DC01134B8C7D""",
      """DD37BC9F0B3A4788F9B54966F252174C8CE487CBE59C53C22B81BF77621A7CE7
         616DCB5B1E2EE63C2C309B""",
      """5F485C637AE30B1E30497F0FB7EC364E13C906E2813DAA34161B7AC4A4FD7A1B
         DDD79601BBD22CEF1F57CBC7""",
      """F6C237FB3CFE95EC8414CC16D203B4874E644CC9A543465CAD2DC563488A659E
         8A2E7C981E2A9F22E5E868FFE1""",
      """DA7AB3291553C659873C95913768953C6E526D3A26590898C0ADE89FF56FBD11
         0F1436AF590B17FED49F8C4B2B1E""",
      """8CFA5FD56EE239CA47737591CBA103E41A18ACF8E8D257B0DBE8851134A81FF6
         B2E97104B39B76E19DA256A17CE52D""",
      """57E89659D878F360AF6DE45A9A5E372EF40C384988E82640A3D5E4B76D2EF181
         780B9A099AC06EF0F8A7F3F764209720""",
      """B91E64235DBD234EEA2AE14A92A173EBE835347239CFF8B02074416F55C6B60D
         C6CED06AE9F8D705505F0D617E4B29AEF9""",
      """E42A67362A581E8CF3D847502215755D7AD425CA030C4360B0F7EF513E698026
         5F61C9FA18DD9CE668F38DBC2A1EF8F83CD6""",
      """634DB92C22010E1CBF1E1623923180406C515272209A8ACC42DE05CC2E96A1E9
         4C1F9F6B93234B7F4C55DE8B1961A3BF352259""",
      """CC6CA3A8CB391CD8A5AFF1FAA7B3FFBDD21A5A3CE66CFADDBFE8B179E4C860BE
         5EC66BD2C6DE6A39A25622F9F2FCB3FC05AF12B5""",
      """7C0E6A0D35F8AC854C7245EBC73693731BBBC3E6FAB644466DE27BB522FCB993
         07126AE718FE8F00742E6E5CB7A687C88447CBC961""",
      """C5581D40B331E24003901BD6BF244ACA9E9601B9D81252BB38048642731F1146
         B8A4C69F88E148B2C8F8C14F15E1D6DA57B2DAA9991E""",
      """EC6B4A88713DF27C0F2D02E738B69DB43ABDA3921317259C864C1C386E9A5A3F
         533DC05F3BEEB2BEC2AAC8E06DB4C6CB3CDDCF697E03D5""",
      """0321736BEBA578E90ABC1A90AA56157D871618F6DE0D764CC8C91E06C68ECD3B
         9DE3824064503384DB67BEB7FE012232DACAEF93A000FBA7""",
      """D0A249A97B5F1486721A50D4C4AB3F5D674A0E29925D5BF2678EF6D8D521E456
         BD84AA755328C83FC890837726A8E7877B570DBA39579AABDD""",
      """C32138531118F08C7DCC292428AD20B45AB27D9517A18445F38B8F0C2795BCDF
         E3FFE384E65ECBF74D2C9D0DA88398575326074904C1709BA072""",
      """B0F4CFB939EA785EABB7E7CA7C476CDD9B227F015D905368BA00AE96B9AAF720
         297491B3921267576B72C8F58D577617E844F9F0759B399C6B064C""",
      """BD02E51B0CF2C2B8D204A026B41A66FBFC2AC37EE9411FC449C8D1194A0792A2
         8EE731407DFC89B6DFC2B10FAA27723A184AFEF8FD83DEF858A32D3F""",
      """E33146B83E4BB671392218DA9A77F8D9F5974147182FB95BA662CB66011989C1
         6D9AF104735D6F79841AA4D1DF276615B50108DF8A29DBC9DE31F4260D""",
      """411C13C75073C1E2D4B1ECF13139BA9656CD35C14201F1C7C6F0EEB58D2DBFE3
         5BFDECCC92C3961CFABB590BC1EB77EAC15732FB0275798680E0C7292E50""",
      """F2C76EF617FA2BFC8A4D6BCBB15FE88436FDC2165D3074629579079D4D5B86F5
         081AB177B4C3F530376C9C924CBD421A8DAF8830D0940C4FB7589865830699""",
      """45927E32DDF801CAF35E18E7B5078B7F5435278212EC6BB99DF884F49B327C64
         86FEAE46BA187DC1CC9145121E1492E6B06E9007394DC33B7748F86AC3207CFE"""
    ]

    Digests = [
      "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
      "C1DFD96EEA8CC2B62785275BCA38AC261256E278",
      "0A1C2D555BBE431AD6288AF5A54F93E0449C9232",
      "BF36ED5D74727DFD5D7854EC6B1D49468D8EE8AA",
      "B78BAE6D14338FFCCFD5D5B5674A275F6EF9C717",
      "60B7D5BB560A1ACF6FA45721BD0ABB419A841A89",
      "A6D338459780C08363090FD8FC7D28DC80E8E01F",
      "860328D80509500C1783169EBF0BA0C4B94DA5E5",
      "24A2C34B976305277CE58C2F42D5092031572520",
      "411CCEE1F6E3677DF12698411EB09D3FF580AF97",
      "05C915B5ED4E4C4AFFFC202961F3174371E90B5C",
      "AF320B42D7785CA6C8DD220463BE23A2D2CB5AFC",
      "9F4E66B6CEEA40DCF4B9166C28F1C88474141DA9",
      "E6C4363C0852951991057F40DE27EC0890466F01",
      "046A7B396C01379A684A894558779B07D8C7DA20",
      "D58A262EE7B6577C07228E71AE9B3E04C8ABCDA9",
      "A150DE927454202D94E656DE4C7C0CA691DE955D",
      "35A4B39FEF560E7EA61246676E1B7E13D587BE30",
      "7CE69B1ACDCE52EA7DBD382531FA1A83DF13CAE7",
      "B47BE2C64124FA9A124A887AF9551A74354CA411",
      "8BB8C0D815A9C68A1D2910F39D942603D807FBCC",
      "B486F87FB833EBF0328393128646A6F6E660FCB1",
      "76159368F99DECE30AADCFB9B7B41DAB33688858",
      "DBC1CB575CE6AEB9DC4EBF0F843BA8AEB1451E89",
      "D7A98289679005EB930AB75EFD8F650F991EE952",
      "FDA26FA9B4874AB701ED0BB64D134F89B9C4CC50",
      "C2FF7CCDE143C8F0601F6974B1903EB8D5741B6E",
      "643C9DC20A929608F6CAA9709D843CA6FA7A76F4",
      "509EF787343D5B5A269229B961B96241864A3D74",
      "B61CE538F1A1E6C90432B233D7AF5B6524EBFBE3",
      "5B7B94076B2FC20D6ADB82479E6B28D07C902B75",
      "6066DB99FC358952CF7FB0EC4D89CB0158ED91D7",
      "B89962C94D60F6A332FD60F6F07D4F032A586B76",
      "17BDA899C13D35413D2546212BCD8A93CEB0657B",
      "BADCDD53FDC144B8BF2CC1E64D10F676EEBE66ED",
      "01B4646180F1F6D2E06BBE22C20E50030322673A",
      "10016DC3A2719F9034FFCC689426D28292C42FC9",
      "9F42FA2BCE6EF021D93C6B2D902273797E426535",
      "CDF48BACBFF6F6152515323F9B43A286E0CB8113",
      "B88FB75274B9B0FD57C0045988CFCEF6C3CE6554",
      "C06D3A6A12D9E8DB62E8CFF40CA23820D61D8AA7",
      "6E40F9E83A4BE93874BC97CDEBB8DA6889AE2C7A",
      "3EFC940C312EF0DFD4E1143812248DB89542F6A5",
      "A0CF03F7BADD0C3C3C4EA3717F5A4FB7E67B2E56",
      "A544E06F1A07CEB175A51D6D9C0111B3E15E9859",
      "199D986ED991B99A071F450C6B1121A727E8C735",
      "33BAC6104B0AD6128D091B5D5E2999099C9F05DE",
      "76D7DB6E18C1F4AE225CE8CCC93C8F9A0DFEB969",
      "F652F3B1549F16710C7402895911E2B86A9B2AEE",
      "63FAEBB807F32BE708CF00FC35519991DC4E7F68",
      "0E6730BC4A0E9322EA205F4EDFFF1FFFDA26AF0A",
      "B61A3A6F42E8E6604B93196C43C9E84D5359E6FE",
      "32D979CA1B3ED0ED8C890D99EC6DD85E6C16ABF4",
      "6F18190BD2D02FC93BCE64756575CEA36D08B1C3",
      "68F525FEEA1D8DBE0117E417CA46708D18D7629A",
      "A7272E2308622FF7A339460ADC61EFD0EA8DABDC",
      "AEF843B86916C16F66C84D83A6005D23FD005C9E",
      "BE2CD6F380969BE59CDE2DFF5E848A44E7880BD6",
      "E5EB4543DEEE8F6A5287845AF8B593A95A9749A1",
      "534C850448DD486787B62BDEC2D4A0B140A1B170",
      "6FBFA6E4EDCE4CC85A845BF0D228DC39ACEFC2FA",
      "018872691D9B04E8220E09187DF5BC5FA6257CD9",
      "D98D512A35572F8BD20DE62E9510CC21145C5BF4",
      "9F3EA255F6AF95C5454E55D7354CABB45352EA0B",
      "A70CFBFE7563DD0E665C7C6715A96A8D756950C0",
    ]

    Digest1MillionA = "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F"

  test "SHA1 block size":
    var ctx: sha1
    check:
      sha1.sizeBlock == 64
      ctx.sizeBlock == 64

  test "SHA1 digest size":
    var ctx: sha1
    check:
      sha1.sizeDigest == 20
      ctx.sizeDigest == 20

  test "SHA1 compile-time test vectors":
    const
      check0 = sha1.digest(fromHex(stripSpaces(Messages[0])))
      check1 = sha1.digest(fromHex(stripSpaces(Messages[1])))
      check2 = sha1.digest(fromHex(stripSpaces(Messages[2])))
      check3 = sha1.digest(fromHex(stripSpaces(Messages[3])))
      check4 = sha1.digest(fromHex(stripSpaces(Messages[4])))
      check5 = sha1.digest(fromHex(stripSpaces(Messages[5])))
      check6 = sha1.digest(fromHex(stripSpaces(Messages[6])))
      check7 = sha1.digest(fromHex(stripSpaces(Messages[7])))
      check8 = sha1.digest(fromHex(stripSpaces(Messages[8])))
      check9 = sha1.digest(fromHex(stripSpaces(Messages[9])))
      check10 = sha1.digest(fromHex(stripSpaces(Messages[10])))
      check11 = sha1.digest(fromHex(stripSpaces(Messages[11])))
      check12 = sha1.digest(fromHex(stripSpaces(Messages[12])))
      check13 = sha1.digest(fromHex(stripSpaces(Messages[13])))
      check14 = sha1.digest(fromHex(stripSpaces(Messages[14])))
      check15 = sha1.digest(fromHex(stripSpaces(Messages[15])))
      check16 = sha1.digest(fromHex(stripSpaces(Messages[16])))
      check17 = sha1.digest(fromHex(stripSpaces(Messages[17])))
      check18 = sha1.digest(fromHex(stripSpaces(Messages[18])))
      check19 = sha1.digest(fromHex(stripSpaces(Messages[19])))
      check20 = sha1.digest(fromHex(stripSpaces(Messages[20])))
      check21 = sha1.digest(fromHex(stripSpaces(Messages[21])))
      check22 = sha1.digest(fromHex(stripSpaces(Messages[22])))
      check23 = sha1.digest(fromHex(stripSpaces(Messages[23])))
      check24 = sha1.digest(fromHex(stripSpaces(Messages[24])))
      check25 = sha1.digest(fromHex(stripSpaces(Messages[25])))
      check26 = sha1.digest(fromHex(stripSpaces(Messages[26])))
      check27 = sha1.digest(fromHex(stripSpaces(Messages[27])))
      check28 = sha1.digest(fromHex(stripSpaces(Messages[28])))
      check29 = sha1.digest(fromHex(stripSpaces(Messages[29])))
      check30 = sha1.digest(fromHex(stripSpaces(Messages[30])))
      check31 = sha1.digest(fromHex(stripSpaces(Messages[31])))
      check32 = sha1.digest(fromHex(stripSpaces(Messages[32])))
      check33 = sha1.digest(fromHex(stripSpaces(Messages[33])))
      check34 = sha1.digest(fromHex(stripSpaces(Messages[34])))
      check35 = sha1.digest(fromHex(stripSpaces(Messages[35])))
      check36 = sha1.digest(fromHex(stripSpaces(Messages[36])))
      check37 = sha1.digest(fromHex(stripSpaces(Messages[37])))
      check38 = sha1.digest(fromHex(stripSpaces(Messages[38])))
      check39 = sha1.digest(fromHex(stripSpaces(Messages[39])))
      check40 = sha1.digest(fromHex(stripSpaces(Messages[40])))
      check41 = sha1.digest(fromHex(stripSpaces(Messages[41])))
      check42 = sha1.digest(fromHex(stripSpaces(Messages[42])))
      check43 = sha1.digest(fromHex(stripSpaces(Messages[43])))
      check44 = sha1.digest(fromHex(stripSpaces(Messages[44])))
      check45 = sha1.digest(fromHex(stripSpaces(Messages[45])))
      check46 = sha1.digest(fromHex(stripSpaces(Messages[46])))
      check47 = sha1.digest(fromHex(stripSpaces(Messages[47])))
      check48 = sha1.digest(fromHex(stripSpaces(Messages[48])))
      check49 = sha1.digest(fromHex(stripSpaces(Messages[49])))
      check50 = sha1.digest(fromHex(stripSpaces(Messages[50])))
      check51 = sha1.digest(fromHex(stripSpaces(Messages[51])))
      check52 = sha1.digest(fromHex(stripSpaces(Messages[52])))
      check53 = sha1.digest(fromHex(stripSpaces(Messages[53])))
      check54 = sha1.digest(fromHex(stripSpaces(Messages[54])))
      check55 = sha1.digest(fromHex(stripSpaces(Messages[55])))
      check56 = sha1.digest(fromHex(stripSpaces(Messages[56])))
      check57 = sha1.digest(fromHex(stripSpaces(Messages[57])))
      check58 = sha1.digest(fromHex(stripSpaces(Messages[58])))
      check59 = sha1.digest(fromHex(stripSpaces(Messages[59])))
      check60 = sha1.digest(fromHex(stripSpaces(Messages[60])))
      check61 = sha1.digest(fromHex(stripSpaces(Messages[61])))
      check62 = sha1.digest(fromHex(stripSpaces(Messages[62])))
      check63 = sha1.digest(fromHex(stripSpaces(Messages[63])))
    check:
      $check0 == Digests[0]
      $check1 == Digests[1]
      $check2 == Digests[2]
      $check3 == Digests[3]
      $check4 == Digests[4]
      $check5 == Digests[5]
      $check6 == Digests[6]
      $check7 == Digests[7]
      $check8 == Digests[8]
      $check9 == Digests[9]
      $check10 == Digests[10]
      $check11 == Digests[11]
      $check12 == Digests[12]
      $check13 == Digests[13]
      $check14 == Digests[14]
      $check15 == Digests[15]
      $check16 == Digests[16]
      $check17 == Digests[17]
      $check18 == Digests[18]
      $check19 == Digests[19]
      $check20 == Digests[20]
      $check21 == Digests[21]
      $check22 == Digests[22]
      $check23 == Digests[23]
      $check24 == Digests[24]
      $check25 == Digests[25]
      $check26 == Digests[26]
      $check27 == Digests[27]
      $check28 == Digests[28]
      $check29 == Digests[29]
      $check30 == Digests[30]
      $check31 == Digests[31]
      $check32 == Digests[32]
      $check33 == Digests[33]
      $check34 == Digests[34]
      $check35 == Digests[35]
      $check36 == Digests[36]
      $check37 == Digests[37]
      $check38 == Digests[38]
      $check39 == Digests[39]
      $check40 == Digests[40]
      $check41 == Digests[41]
      $check42 == Digests[42]
      $check43 == Digests[43]
      $check44 == Digests[44]
      $check45 == Digests[45]
      $check46 == Digests[46]
      $check47 == Digests[47]
      $check48 == Digests[48]
      $check49 == Digests[49]
      $check50 == Digests[50]
      $check51 == Digests[51]
      $check52 == Digests[52]
      $check53 == Digests[53]
      $check54 == Digests[54]
      $check55 == Digests[55]
      $check56 == Digests[56]
      $check57 == Digests[57]
      $check58 == Digests[58]
      $check59 == Digests[59]
      $check60 == Digests[60]
      $check61 == Digests[61]
      $check62 == Digests[62]
      $check63 == Digests[63]

  test "SHA1 test vectors":
    for i in 0..<len(Messages):
      var msg: seq[byte]
      if len(Messages[i]) > 0:
        msg = fromHex(stripSpaces(Messages[i]))
      var edigest = fromHex(stripSpaces(Digests[i]))
      var cdigest3: array[20, byte]
      var ctx1, ctx2: sha1
      ctx1.init()
      ctx2.init()
      ctx1.update(msg)
      if len(msg) > 0:
        ctx2.update(addr msg[0], uint(len(msg)))
      else:
        ctx2.update(nil, 0)
      var cdigest1 = ctx1.finish()
      var cdigest2 = sha1.digest(msg)
      var cdigest4: string
      if len(msg) > 0:
        cdigest4 = $sha1.digest(addr msg[0], uint(len(msg)))
      else:
        cdigest4 = $sha1.digest(nil, 0)
      discard ctx2.finish(cdigest3)
      ctx1.clear()
      ctx2.clear()
      check:
        edigest == cdigest1.data
        edigest == cdigest2.data
        edigest == cdigest3
        edigest == fromHex(cdigest4)
        isFullZero(ctx1) == true
        isFullZero(ctx2) == true

  test "SHA1 empty update() test":
    var data: seq[byte]
    var ctx1, ctx2: sha1
    var msg = fromHex(stripSpaces(Messages[1]))
    var edigest = fromHex(stripSpaces(Digests[1]))
    ctx1.init()
    ctx2.init()
    ctx1.update(msg)
    ctx2.update(addr msg[0], uint(len(msg)))
    ctx1.update(data)
    ctx2.update(nil, 0)
    check:
      ctx1.finish().data == edigest
      ctx2.finish().data == edigest

  test "SHA1 million test":
    var ctx: sha1
    var edigest = fromHex(stripSpaces(Digest1MillionA))
    var am = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ctx.init()
    for i in 0..(15625 - 1):
      ctx.update(am)
    var cdigest = ctx.finish()
    check:
      cdigest.data == edigest
