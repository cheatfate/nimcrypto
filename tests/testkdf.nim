import nimcrypto/pbkdf2, nimcrypto/hmac, nimcrypto/sha2, nimcrypto/utils
import nimcrypto/sha
import unittest

when defined(nimHasUsed): {.used.}

suite "PBKDF2-HMAC-SHA1/SHA224/256/384/512 tests suite":

  const
    passwords224 = [
      "passDATAb00AB7YxDTTlRH2dqxD",
      "passDATAb00AB7YxDTTlRH2dqxDx",
      "passDATAb00AB7YxDTTlRH2dqxDx1",
      "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5",
      "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57",
      "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U",
      """passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U
         n4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi0""",
      """passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U
         n4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04""",
      """passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U
         n4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04U""",
      """passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U
         n4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04Uz
         3ebEAhzZ4ve1A2wg5CnLXdZC5Y7gwfVgbEgZSTmoYQSzC5OW4dfrjqiwApTACO6xo
         OL1AjWj6X6f6qFfF8TVmOzU9RhOd1N4QtzWI4fP6FYttNz5FuLdtYVXWVXH2Tf7I9
         fieMeWCHTMkM4VcmQyQHpbcP8MEb5f1g6Ckg5xk3HQr3wMBvQcOHpCPy1K8HCM7a5
         wkPDhgVA0BVmwNpsRIbDQZRtHK6dT6bGyalp6gbFZBuBHwD86gTzkrFY7HkOVrgc0
         gJcGJZe65Ce8v4Jn5OzkuVsiU8efm2Pw2RnbpWSAr7SkVdCwXK2XSJDQ5fZ4HBEz9
         VTFYrG23ELuLjvx5njOLNgDAJuf5JB2tn4nMjjcnl1e8qcYVwZqFzEv2zhLyDWMkV
         4tzl4asLnvyAxTBkxPRZj2pRABWwb3kEofpsHYxMTAn38YSpZreoXipZWBnu6HDUR
         aruXaIPYFPYHl9Ls9wsuD7rzaGfbOyfVgLIGK5rODphwRA7lm88bGKY8b7tWOtepy
         EvaLxMI7GZF5ScwpZTYeEDNUKPzvM2Im9zehIaznpguNdNXNMLWnwPu4H6zEvajkw
         3G3ucSiXKmh6XNe3hkdSANm3vnxzRXm4fcuzAx68IElXE2bkGFElluDLo6EsUDWZ4
         JIWBVaDwYdJx8uCXbQdoifzCs5kuuClaDaDqIhb5hJ2WR8mxiueFsS0aDGdIYmye5
         svmNmzQxFmdOkHoF7CfwuU1yy4uEEt9vPSP2wFp1dyaMvJW68vtB4kddLmI6gIgVV
         cT6ZX1Qm6WsusPrdisPLB2ScodXojCbL3DLj6PKG8QDVMWTrL1TpafT2wslRledWI
         hsTlv2mI3C066WMcTSwKLXdEDhVvFJ6ShiLKSN7gnRrlE0BnAw"""
    ]

    salts224 = [
      "saltKEYbcTcXHCBxtjD2PnBh44A",
      "saltKEYbcTcXHCBxtjD2PnBh44AI",
      "saltKEYbcTcXHCBxtjD2PnBh44AIQ",
      "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe",
      "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJem",
      "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk",
      """saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk
         URWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy""",
      """saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk
         URWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6""",
      """saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk
         URWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6P""",
      """saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk
         URWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6Pl
         BdILBOkKUB6TGTPJXh1tpdOHTG6KuIvcbQp9qWjaf1uxAKgiTtYRIHhxjJI2viVa6
         fDZ67QOouOaf2RXQhpsWaTtAVnff6PIFcvJhdPDFGV5nvmZWoCZQodj6yXRDHPw9P
         yF0iLYm9uFtEunlAAxGB5qqea4X5tZvB1OfLVwymY3a3JPjdxTdvHxCHbqqE0zip6
         1JNqdmeWxGtlRBC6CGoCiHO4XxHCntQBRJDcG0zW7joTdgtTBarsQQhlLXBGMNBSN
         mmTbDf3hFtawUBCJH18IAiRMwyeQJbJ2bERsY3MVRPuYCf4Au7gN72iGh1lRktSQt
         EFye7pO46kMXRrEjHQWXInMzzy7X2StXUzHVTFF2VdOoKn0WUqFNvB6PF7qIsOlYK
         j57bi1Psa34s85WxMSbTkhrd7VHdHZkTVaWdraohXYOePdeEvIwObCGEXkETUzqM5
         P2yzoBOJSdjpIYaa8zzdLD3yrb1TwCZuJVxsrq0XXY6vErU4QntsW0972XmGNyumF
         NJiPm4ONKh1RLvS1kddY3nm8276S4TUuZfrRQO8QxZRNuSaZI8JRZp5VojB5DktuM
         xAQkqoPjQ5Vtb6oXeOyY591CB1MEW1fLTCs0NrL321SaNRMqza1ETogAxpEiYwZ6p
         IgnMmSqNMRdZnCqA4gMWw1lIVATWK83OCeicNRUNOdfzS7A8vbLcmvKPtpOFvhNzw
         rrUdkvuKvaYJviQgeR7snGetO9JLCwIlHIj52gMCNU18d32SJl7Xomtl3wIe02SMv
         q1i1BcaX7lXioqWGmgVqBWU3fsUuGwHi6RUKCCQdEOBfNo2WdpFaCflcgnn0O6jVH
         Cqkv8cQk81AqS00rAmHGCNTwyA6Tq5TXoLlDnC8gAQjDUsZp0z""",
    ]

    expects224_1 = [
      "86AB2F3D0CB39839B46DA2DD8F210915D79AD2E6F2093D155D75C8D998",
      "59166E22A2A28E63B3B80D5C405688FF28FEB4BC3A510B4256AA38308A",
      "E18889591C39BC3E51108A06523D72ED3E6C69A19D32E2B6E1367F8199",
      "A3591C39D30043853E4C14151D7422AF20C522F7F12BF3A5AAC6EDE452",
      "50C6EEE0C51330354A4D25BC9AC4DA28BA522F1543BD317A4A04C82298",
      "C722E759039FC9441326932960800BC46C745211650048000E98FFAD8A",
      "04701CA247B89139C48F6C6DFF1728416AC14A0B4F4D706EF7864C77DE",
      "6FB6E0BF665D13367D3E7BD0DC0C3B9191A1B7EFFF9ABC86D00DDE830F",
      "F859E315F4A2530813B922CB27652E6FCF493B48AF21EBE911645D0220",
      "3AC48169D31F2561B4B18BD6A616BB42A5EFB1F8B700F5759C92CEAE92"
    ]

    lengths224 = [
      28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
      27, 27, 27, 27, 27, 27, 27, 27, 27, 27,
      29, 29, 29, 29, 29, 29, 29, 29, 29, 29
    ]

    passwords256 = [
      "passDATAb00AB7YxDTTlRH2dqxDx19G",
      "passDATAb00AB7YxDTTlRH2dqxDx19GD",
      "passDATAb00AB7YxDTTlRH2dqxDx19GDx",
      "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5",
      "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57",
      "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U",
      """passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U
         n4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi0""",
      """passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U
         n4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04""",
      """passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U
         n4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04U""",
      """passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U
         n4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04Uz
         3ebEAhzZ4ve1A2wg5CnLXdZC5Y7gwfVgbEgZSTmoYQSzC5OW4dfrjqiwApTACO6xo
         OL1AjWj6X6f6qFfF8TVmOzU9RhOd1N4QtzWI4fP6FYttNz5FuLdtYVXWVXH2Tf7I9
         fieMeWCHTMkM4VcmQyQHpbcP8MEb5f1g6Ckg5xk3HQr3wMBvQcOHpCPy1K8HCM7a5
         wkPDhgVA0BVmwNpsRIbDQZRtHK6dT6bGyalp6gbFZBuBHwD86gTzkrFY7HkOVrgc0
         gJcGJZe65Ce8v4Jn5OzkuVsiU8efm2Pw2RnbpWSAr7SkVdCwXK2XSJDQ5fZ4HBEz9
         VTFYrG23ELuLjvx5njOLNgDAJuf5JB2tn4nMjjcnl1e8qcYVwZqFzEv2zhLyDWMkV
         4tzl4asLnvyAxTBkxPRZj2pRABWwb3kEofpsHYxMTAn38YSpZreoXipZWBnu6HDUR
         aruXaIPYFPYHl9Ls9wsuD7rzaGfbOyfVgLIGK5rODphwRA7lm88bGKY8b7tWOtepy
         EvaLxMI7GZF5ScwpZTYeEDNUKPzvM2Im9zehIaznpguNdNXNMLWnwPu4H6zEvajkw
         3G3ucSiXKmh6XNe3hkdSANm3vnxzRXm4fcuzAx68IElXE2bkGFElluDLo6EsUDWZ4
         JIWBVaDwYdJx8uCXbQdoifzCs5kuuClaDaDqIhb5hJ2WR8mxiueFsS0aDGdIYmye5
         svmNmzQxFmdOkHoF7CfwuU1yy4uEEt9vPSP2wFp1dyaMvJW68vtB4kddLmI6gIgVV
         cT6ZX1Qm6WsusPrdisPLB2ScodXojCbL3DLj6PKG8QDVMWTrL1TpafT2wslRledWI
         hsTlv2mI3C066WMcTSwKLXdEDhVvFJ6ShiLKSN7gnRrlE0BnAw"""
    ]

    salts256 = [
      "saltKEYbcTcXHCBxtjD2PnBh44AIQ6X",
      "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XU",
      "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUO",
      "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe",
      "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJem",
      "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk",
      """saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk
         URWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy""",
      """saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk
         URWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6""",
      """saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk
         URWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6P""",
      """saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk
         URWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6Pl
         BdILBOkKUB6TGTPJXh1tpdOHTG6KuIvcbQp9qWjaf1uxAKgiTtYRIHhxjJI2viVa6
         fDZ67QOouOaf2RXQhpsWaTtAVnff6PIFcvJhdPDFGV5nvmZWoCZQodj6yXRDHPw9P
         yF0iLYm9uFtEunlAAxGB5qqea4X5tZvB1OfLVwymY3a3JPjdxTdvHxCHbqqE0zip6
         1JNqdmeWxGtlRBC6CGoCiHO4XxHCntQBRJDcG0zW7joTdgtTBarsQQhlLXBGMNBSN
         mmTbDf3hFtawUBCJH18IAiRMwyeQJbJ2bERsY3MVRPuYCf4Au7gN72iGh1lRktSQt
         EFye7pO46kMXRrEjHQWXInMzzy7X2StXUzHVTFF2VdOoKn0WUqFNvB6PF7qIsOlYK
         j57bi1Psa34s85WxMSbTkhrd7VHdHZkTVaWdraohXYOePdeEvIwObCGEXkETUzqM5
         P2yzoBOJSdjpIYaa8zzdLD3yrb1TwCZuJVxsrq0XXY6vErU4QntsW0972XmGNyumF
         NJiPm4ONKh1RLvS1kddY3nm8276S4TUuZfrRQO8QxZRNuSaZI8JRZp5VojB5DktuM
         xAQkqoPjQ5Vtb6oXeOyY591CB1MEW1fLTCs0NrL321SaNRMqza1ETogAxpEiYwZ6p
         IgnMmSqNMRdZnCqA4gMWw1lIVATWK83OCeicNRUNOdfzS7A8vbLcmvKPtpOFvhNzw
         rrUdkvuKvaYJviQgeR7snGetO9JLCwIlHIj52gMCNU18d32SJl7Xomtl3wIe02SMv
         q1i1BcaX7lXioqWGmgVqBWU3fsUuGwHi6RUKCCQdEOBfNo2WdpFaCflcgnn0O6jVH
         Cqkv8cQk81AqS00rAmHGCNTwyA6Tq5TXoLlDnC8gAQjDUsZp0z"""
    ]

    expects256_1 = [
      "089314BCDFF35115C3240C0CEE274C114C7BC49FD498F853928A385528C9D9C34D",
      "806E79AEA28676B851B61D6D76E55DD49DC6781E50B76E2C1F32A2FFAEE91624BB",
      "CCDE3C818E49B7CA1103A9C88597AC4B516E600F8084372901E1E88F56277FC50F",
      "3B28BF8995D81DDF78040C36D2E22C3B7C674BA05F91F11E3319BFB6FC8AC69EFA",
      "43B34EC2B78FB5E1ABA41A5453F733C65B6604626D0F0C0BCC275CDC32F4717BC8",
      "57547F8DDB48E9F9926723050AFB0ADFA48F0FB8C0D7274448F55595FEBEC5EAD8",
      "2212BB287D744DEF4CC1BC51EE73EE191966BCF7B1F62A98DD2632783C3301BDE3",
      "D5B7964768AAE8B3293CEDB72B061ADF08ADB2FC75536330CBB41F1C03BC699E08",
      "F83D917F329DA4A215F5350BB7C4A614854184F6FAF204D352C73E6F345B22C88C",
      "4D7AB8C17E8906EF0D8BF41835A41138FA844C7949AC4567108008284DB323F7CE"
    ]

    lengths256 = [
      32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
      31, 31, 31, 31, 31, 31, 31, 31, 31, 31,
      30, 30, 30, 30, 30, 30, 30, 30, 30, 30
    ]

    passwords384 = [
      "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"""
    ]

    salts384 = [
      "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"""
    ]

    expects384_1 = [
      """0644A3489B088AD85A0E42BE3E7F82500EC18936699151A2C90497151BAC7BB6
         9300386A5E798795BE3CEF0A3C80322727""",
      """5327A9B0404B5EF1D6B549CFE79B5964A364573FF064C7BB3DE5261F1E3339CF
         A84B7F119D1B339EF4206E8153421058F6""",
      """BFC71B98216331E54ABF9721960CFCE590929D84AF0A5C4E2FF94CBED930E4F1
         A9B0D04314E67DCE37957B0B4086E95E68""",
      """EA4B16B1EDB94F5C78B0BE147258D541C2A880234A3A05E7C83CF5D854A96538
         B840B26783AFA2AAD5FB8F112DA06D265A""",
      """08CA2381997469622780C1D1D772EC76421B790C2C10E7445E4E95CF80351371
         B01DB77D561CD2CE048EA3C0C8982A888A""",
      """423D567B80E7B35F6245F60773F7BB541D172B3561D88C5957018F94A88C8803
         9AACCA7D6FC6F80B81098182B9B6021366""",
      """7CA65CCB5BC07CDC48B7276550EC665D1FF9415B9159B1134BBAE4F5A22D2890
         403A8ED546F2B089C05A91F8FA9A48AA33""",
      """3B23D550AF6EAFFC3C5D85424650E7BA0EEB922E770F1BBF4866C1DD6BE88725
         D094C70363541FEBAA1F6C884268B1EF2B""",
      """6EFA254DEB90B4D39A45AB32F3FBA9D16C22673CB38E23247CC906DED50F67D8
         3853B8566CFBABC3CC9B6B34ED4B8A4083""",
      """561F536EE9AD505C3FC531D70EA2CAD76EE5B9B790BD5A76565F793503B06832
         8CA6C28AC3CA6D29CC0B634EE5051C19C0"""
    ]

    lengths384 = [
      48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
      47, 47, 47, 47, 47, 47, 47, 47, 47, 47,
      49, 49, 49, 49, 49, 49, 49, 49, 49, 49
    ]

    passwords512 = [
      "passDATAb00AB7YxDTT",
      "passDATAb00AB7YxDTTl",
      "passDATAb00AB7YxDTTlR",
      "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5",
      "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57",
      "passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U",
      """passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U
         n4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi0""",
      """passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U
         n4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04""",
      """passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U
         n4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04U""",
      """passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U
         n4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04Uz
         3ebEAhzZ4ve1A2wg5CnLXdZC5Y7gwfVgbEgZSTmoYQSzC5OW4dfrjqiwApTACO6xo
         OL1AjWj6X6f6qFfF8TVmOzU9RhOd1N4QtzWI4fP6FYttNz5FuLdtYVXWVXH2Tf7I9
         fieMeWCHTMkM4VcmQyQHpbcP8MEb5f1g6Ckg5xk3HQr3wMBvQcOHpCPy1K8HCM7a5
         wkPDhgVA0BVmwNpsRIbDQZRtHK6dT6bGyalp6gbFZBuBHwD86gTzkrFY7HkOVrgc0
         gJcGJZe65Ce8v4Jn5OzkuVsiU8efm2Pw2RnbpWSAr7SkVdCwXK2XSJDQ5fZ4HBEz9
         VTFYrG23ELuLjvx5njOLNgDAJuf5JB2tn4nMjjcnl1e8qcYVwZqFzEv2zhLyDWMkV
         4tzl4asLnvyAxTBkxPRZj2pRABWwb3kEofpsHYxMTAn38YSpZreoXipZWBnu6HDUR
         aruXaIPYFPYHl9Ls9wsuD7rzaGfbOyfVgLIGK5rODphwRA7lm88bGKY8b7tWOtepy
         EvaLxMI7GZF5ScwpZTYeEDNUKPzvM2Im9zehIaznpguNdNXNMLWnwPu4H6zEvajkw
         3G3ucSiXKmh6XNe3hkdSANm3vnxzRXm4fcuzAx68IElXE2bkGFElluDLo6EsUDWZ4
         JIWBVaDwYdJx8uCXbQdoifzCs5kuuClaDaDqIhb5hJ2WR8mxiueFsS0aDGdIYmye5
         svmNmzQxFmdOkHoF7CfwuU1yy4uEEt9vPSP2wFp1dyaMvJW68vtB4kddLmI6gIgVV
         cT6ZX1Qm6WsusPrdisPLB2ScodXojCbL3DLj6PKG8QDVMWTrL1TpafT2wslRledWI
         hsTlv2mI3C066WMcTSwKLXdEDhVvFJ6ShiLKSN7gnRrlE0BnAw"""
    ]

    salts512 = [
      "saltKEYbcTcXHCBxtjD",
      "saltKEYbcTcXHCBxtjD2",
      "saltKEYbcTcXHCBxtjD2P",
      "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe",
      "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJem",
      "saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk",
      """saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk
         URWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy""",
      """saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk
         URWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6""",
      """saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk
         URWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6P""",
      """saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk
         URWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6Pl
         BdILBOkKUB6TGTPJXh1tpdOHTG6KuIvcbQp9qWjaf1uxAKgiTtYRIHhxjJI2viVa6
         fDZ67QOouOaf2RXQhpsWaTtAVnff6PIFcvJhdPDFGV5nvmZWoCZQodj6yXRDHPw9P
         yF0iLYm9uFtEunlAAxGB5qqea4X5tZvB1OfLVwymY3a3JPjdxTdvHxCHbqqE0zip6
         1JNqdmeWxGtlRBC6CGoCiHO4XxHCntQBRJDcG0zW7joTdgtTBarsQQhlLXBGMNBSN
         mmTbDf3hFtawUBCJH18IAiRMwyeQJbJ2bERsY3MVRPuYCf4Au7gN72iGh1lRktSQt
         EFye7pO46kMXRrEjHQWXInMzzy7X2StXUzHVTFF2VdOoKn0WUqFNvB6PF7qIsOlYK
         j57bi1Psa34s85WxMSbTkhrd7VHdHZkTVaWdraohXYOePdeEvIwObCGEXkETUzqM5
         P2yzoBOJSdjpIYaa8zzdLD3yrb1TwCZuJVxsrq0XXY6vErU4QntsW0972XmGNyumF
         NJiPm4ONKh1RLvS1kddY3nm8276S4TUuZfrRQO8QxZRNuSaZI8JRZp5VojB5DktuM
         xAQkqoPjQ5Vtb6oXeOyY591CB1MEW1fLTCs0NrL321SaNRMqza1ETogAxpEiYwZ6p
         IgnMmSqNMRdZnCqA4gMWw1lIVATWK83OCeicNRUNOdfzS7A8vbLcmvKPtpOFvhNzw
         rrUdkvuKvaYJviQgeR7snGetO9JLCwIlHIj52gMCNU18d32SJl7Xomtl3wIe02SMv
         q1i1BcaX7lXioqWGmgVqBWU3fsUuGwHi6RUKCCQdEOBfNo2WdpFaCflcgnn0O6jVH
         Cqkv8cQk81AqS00rAmHGCNTwyA6Tq5TXoLlDnC8gAQjDUsZp0z"""
    ]

    expects512_1 = [
      """CBE6088AD4359AF42E603C2A33760EF9D4017A7B2AAD10AF46F992C660A0B461
         ECB0DC2A79C2570941BEA6A08D15D6887E79F32B132E1C134E9525EEDDD744FA88""",
      """8E5074A9513C1F1512C9B1DF1D8BFFA9D8B4EF9105DFC16681222839560FB632
         64BED6AABF761F180E912A66E0B53D65EC88F6A1519E14804EBA6DC9DF1370070B""",
      """A6AC8C048A7DFD7B838DA88F22C3FAB5BFF15D7CB8D83A62C6721A8FAF6903EA
         B6152CB7421026E36F2FFEF661EB4384DC276495C71B5CAB72E1C1A38712E56B93""",
      """E2CCC7827F1DD7C33041A98906A8FD7BAE1920A55FCB8F831683F14F1C397935
         1CB868717E5AB342D9A11ACF0B12D3283931D609B06602DA33F8377D1F1F9902DA""",
      """B029A551117FF36977F283F579DC7065B352266EA243BDD3F920F24D4D141ED8
         B6E02D96E2D3BDFB76F8D77BA8F4BB548996AD85BB6F11D01A015CE518F9A71780""",
      """28B8A9F644D6800612197BB74DF460272E2276DE8CC07AC4897AC24DBC6EB774
         99FCAF97415244D9A29DA83FC347D09A5DBCFD6BD63FF6E410803DCA8A900AB671""",
      """16226C85E4F8D604573008BFE61C10B6947B53990450612DD4A3077F7DEE2116
         229E68EFD1DF6D73BD3C6D07567790EEA1E8B2AE9A1B046BE593847D9441A1B766""",
      """880C58C316D3A5B9F05977AB9C60C10ABEEBFAD5CE89CAE62905C1C4F80A0A09
         8D82F95321A6220F8AECCFB45CE6107140899E8D655306AE6396553E2851376C57""",
      """93B9BA8283CC17D50EF3B44820828A258A996DE258225D24FB59990A6D0DE82D
         FB3FE2AC201952100E4CC8F06D883A9131419C0F6F5A6ECB8EC821545F14ADF199""",
      """384BCD6914407E40C295D1037CF4F990E8F0E720AF43CB706683177016D36D1A
         14B3A7CF22B5DF8D5D7D44D69610B64251ADE2E7AB54A3813A89935592E391BF91"""
    ]

    lengths512 = [
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
      63, 63, 63, 63, 63, 63, 63, 63, 63, 63,
      65, 65, 65, 65, 65, 65, 65, 65, 65, 65
    ]

    # PBKDF2[HMAC-SHA1] test vectors obtained from
    # https://www.ietf.org/rfc/rfc6070.txt
    passwords1 = [
      "70617373776F7264",
      "70617373776F7264",
      "70617373776F7264",
      "70617373776F726450415353574F524470617373776F7264",
      "7061737300776F7264"
    ]

    salts1 = [
      "73616C74",
      "73616C74",
      "73616C74",
      """73616C7453414C5473616C7453414C5473616C7453414C5473616C7453414C5473616C
         74""",
      "7361006C74"
    ]

    lengths1 = [
      20, 20, 20, 25, 16
    ]

    runs1 = [
      1, 2, 4096, 4096, 4096
    ]

    expects1 = [
      "0C60C80F961F0E71F3A9B524AF6012062FE037A6",
      "EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957",
      "4B007901B765489ABEAD49D926F721D065A429C1",
      "3D2EEC4FE41C849B80C8D83662C0E44A8B291A964CF2F07038",
      "56FA6AA75548099DCC37D7F03425E0C3"
    ]

  when defined(release):
    const
      expects224_100k = [
        "0ADF2D99E7FF8DBC6B1DF4382D32959021BFDACB99B796BF9089D0E386",
        "B9B9602122E170602C74FDBE3035AB2D4F79143F45C316D1EC8855D6E5",
        "0BD8145365B1EEE1ACF3901E2C10D1B32805DFFEA8EF6CF5F0BA331FB2",
        "3D47B18D8F4ED89039D3807FF3F6D4D9E15C158A8A4588FC8B976A0D52",
        "23E0BE286CDA1D494C584932844EEABDCDFB00CA13A1446DBF0236805A",
        "90EF32BDF05DE7E544BD9DAE97079E29070281B840E0C326F9E0D41845",
        "176D16931083FCBA6AD8C17986B02F32EAEFF39BE05713035272A72BBD",
        "7CD15FCB6B49133B3EF3A5CC4FA4D8ED7C262C3461DECEDB48CBFD5824",
        "0C7D005A4604B8D88386289E4ACD89F8F37C642D04281CCAB3FB968219",
        "682991932A00D95276065F7CC0F87D40734654E5DF2CEB8E9E980050C6"
      ]

      expects256_100k = [
        "4A087BE50A80D23CAF4906010CEB7C9BCCBDDAE52380DD60B6DAFF4A2287CA4148",
        "89D738B7AFACEC234157C84390C8357D34CCBF267C2DD14C8D357C4A459F5392E8",
        "8FEA43515B6669B32619916664D03A9547D667BBA4249499D80A0D53E379DC18C9",
        "DE166AF05815A27B3317662E72ECC139B262911F8790CCE62B5D10D9CF4BE3DC6F",
        "78CDCD1505BBF7AF1695173C147398BFBB57A774AA93F8F7A415F87A84C6C03BF3",
        "844E50F6F72A2EA3D5D23BF781DF0F8D3B89BF5D37D609F9B87FDEA6C450867559",
        "42D29932A23F82C16F11F854757D32EB5201A1F46561440DB97D85E1D8C978962E",
        "3D3A047ABF790AABE0EEBB907E4648D4E3202474FE937BF6E5EC8EFE5F30752D56",
        "029D495DC4FF9A27D4BC532B6C9E435A74DDF19087113A207FC8D0FC6F4122085F",
        "25BC2936281DB8D43C6D612B1C6F7A137EC53E0F45777252401813D5AB6C7A0EF8"
      ]

      expects384_100k = [
        """BF625685B48FE6F187A1780C5CB8E1E4A7B0DBD6F551827F7B2B598735EAC158
           D77AFD3602383D9A685D87F8B089AF30FA""",
        """FE592CE1FD70C0920FF48AA8DD43A3AA742C2E5057B9449735520D7CC48CB3C2
           E856FA876CDAFB7230A781345B86136709""",
        """176DA2A560ACD480E9349A4863806638EC83597EBEB3A9635BE10BDD8A5E6F9B
           A4DA87A43FFB87576CA275278428BA4534""",
        """063BAB60400BEEF4CD900922AB48B0E462FD3B470D6671B20980F12CECC31604
           3004AB8C0EC7DE9FC4CC4BD83FB80DE866""",
        """F88A6887496A950B05EBA61208AA5F806627347C9578E36BC10DA54902EE450B
           10082415859BCDA56BD6426A18452981FC""",
        """89559EBF3C501881C8AEA1A34979DF17B5B27A1DAC8327F5F074D85723FE3EE3
           ECFF904E259CDB60D062D0FF2FB7C68ECF""",
        """7F3653532D970DB3EE6866FE7D0BDC03EA3E420656687EA59C14F06BB53F1A12
           AB44C97E4A88F08986A2D507518A7C845B""",
        """53B3E62CB383DC59FFDECAC65B7479D2A6AF3A1F7D0352329FA3BF5C5B3D9918
           95C40F8B521654806B80BE0AD4EFD4F1B0""",
        """96BAFC3E92F9229D8BB40DB067788B1C0B6C970611CAAE960D63DAE8691FF496
           80EAE1E74C8D58A8A375BE6B6DD342E513""",
        """7BADBDA9DBE9D5AB9237268D57ABB235B6B729AEFA9CACDF5E3007136F117823
           1FCFFE3E6437D9EF713EC32887C4B42674"""
      ]

      expects512_100k = [
        """ACCDCD8798AE5CD85804739015EF2A11E32591B7B7D16F76819B30B0D49D80E1
           ABEA6C9822B80A1FDFE421E26F5603ECA8A47A64C9A004FB5AF8229F762FF41F
           7C""",
        """594256B0BD4D6C9F21A87F7BA5772A791A10E6110694F44365CD94670E57F1AE
           CD797EF1D1001938719044C7F018026697845EB9AD97D97DE36AB8786AAB5096
           E7""",
        """94FFC2B1A390B7B8A9E6A44922C330DB2B193ADCF082EECD06057197F35931A9
           D0EC0EE5C660744B50B61F23119B847E658D179A914807F4B8AB8EB9505AF065
           26""",
        """07447401C85766E4AED583DE2E6BF5A675EABE4F3618281C95616F4FC1FDFE6E
           CBC1C3982789D4FD941D6584EF534A78BD37AE02555D9455E8F089FDB4DFB6BB
           30""",
        """31F5CC83ED0E948C05A15735D818703AAA7BFF3F09F5169CAF5DBA6602A05A4D
           5CFF5553D42E82E40516D6DC157B8DAEAE61D3FEA456D964CB2F7F9A63BBBDB5
           9F""",
        """056BC9072A356B7D4DA60DD66F5968C2CAA375C0220EDA6B47EF8E8D105ED68B
           44185FE9003FBBA49E2C84240C9E8FD3F5B2F4F6512FD936450253DB37D10028
           89""",
        """70CF39F14C4CAF3C81FA288FB46C1DB52D19F72722F7BC84F040676D3371C89C
           11C50F69BCFBC3ACB0AB9E92E4EF622727A916219554B2FA121BEDDA97FF3332
           EC""",
        """2668B71B3CA56136B5E87F30E098F6B4371CB5ED95537C7A073DAC30A2D5BE52
           756ADF5BB2F4320CB11C4E16B24965A9C790DEF0CBC62906920B4F2EB84D1D4A
           30""",
        """2575B485AFDF37C260B8F3386D33A60ED929993C9D48AC516EC66B87E06BE54A
           DE7E7C8CB3417C81603B080A8EEFC56072811129737CED96236B9364E22CE3A5
           42""",
        """B8674F6C0CC9F8CF1F1874534FD5AF01FC1504D76C2BC2AA0A75FE4DD5DFD1DA
           F60EA7C85F122BCEEB8772659D601231607726998EAC3F6AAB72EFF7BA349F7F
           D7"""
      ]

  proc compare(x: openarray[byte], y: openarray[byte]): bool =
    result = false
    if len(x) == len(y):
      result = equalMem(unsafeAddr x[0], unsafeAddr y[0], len(x))

  test "PBKDF2-HMAC-SHA1 (1 and 4096 iterations)":
    var ctx: HMAC[sha1]
    var output: array[128, byte]
    for i in 0..<len(lengths1):
      let p = fromHex(stripSpaces(passwords1[i]))
      let s = fromHex(stripSpaces(salts1[i]))
      let e = fromHex(stripSpaces(expects1[i]))
      let length = lengths1[i]
      check:
        pbkdf2(ctx, p, s, runs1[i], output.toOpenArray(0, length - 1)) == length
        compare(toOpenArray(e, 0, length - 1),
                toOpenArray(output, 0, length - 1)) == true

  test "PBKDF2-HMAC-SHA1 compile-time (1 iteration)":
    const
      check0 = pbkdf2(sha1, fromHex(stripSpaces(passwords1[0])),
                      fromHex(stripSpaces(salts1[0])), runs1[0],
                      lengths1[0])
      check1 = pbkdf2(sha1, fromHex(stripSpaces(passwords1[1])),
                      fromHex(stripSpaces(salts1[1])), runs1[1],
                      lengths1[1])
    let expect0 = fromHex(stripSpaces(expects1[0]))
    let expect1 = fromHex(stripSpaces(expects1[1]))
    check:
      compare(toOpenArray(expect0, 0, lengths1[0] - 1),
              toOpenArray(check0, 0, lengths1[0] - 1)) == true
      compare(toOpenArray(expect1, 0, lengths1[1] - 1),
              toOpenArray(check1, 0, lengths1[1] - 1)) == true

  test "PBKDF2-HMAC-SHA224 (1 iteration)":
    var ctx: HMAC[sha224]
    var output: array[128, byte]
    for i in 0..<len(lengths224):
      var index = i mod 10
      let p = stripSpaces(passwords224[index])
      let s = stripSpaces(salts224[index])
      let e = fromHex(stripSpaces(expects224_1[index]))
      let length = lengths224[i]
      check:
        pbkdf2(ctx, p, s, 1, output.toOpenArray(0, length - 1)) == length
        compare(toOpenArray(e, 0, length - 1),
                toOpenArray(output, 0, length - 1)) == true
      burnMem(output)

  test "PBKDF2-HMAC-SHA224 compile-time (1 iteration)":
    const
      check0 = pbkdf2(sha224, passwords224[0], salts224[0], 1, lengths224[0])

    let expect0 = fromHex(stripSpaces(expects224_1[0]))
    check:
      compare(toOpenArray(expect0, 0, lengths224[0] - 1),
              toOpenArray(check0, 0, lengths224[0] - 1)) == true

  when defined(release):
    test "PBKDF2-HMAC-SHA224 (100,000 iterations)":
      var ctx: HMAC[sha224]
      var output: array[128, byte]
      for i in 20..<len(lengths224):
        var index = i mod 10
        let p = stripSpaces(passwords224[index])
        let s = stripSpaces(salts224[index])
        let e = fromHex(stripSpaces(expects224_100k[index]))
        let length = lengths224[i]
        check:
          pbkdf2(ctx, p, s, 100000, output.toOpenArray(0, length - 1)) == length
          compare(toOpenArray(e, 0, length - 1),
                  toOpenArray(output, 0, length - 1)) == true
        burnMem(output)

  test "PBKDF2-HMAC-SHA256 (1 iteration)":
    var ctx: HMAC[sha256]
    var output: array[128, byte]
    for i in 0..<len(lengths256):
      var index = i mod 10
      let p = stripSpaces(passwords256[index])
      let s = stripSpaces(salts256[index])
      let e = fromHex(stripSpaces(expects256_1[index]))
      let length = lengths256[i]
      check:
        pbkdf2(ctx, p, s, 1, output.toOpenArray(0, length - 1)) == length
        compare(toOpenArray(e, 0, length - 1),
                toOpenArray(output, 0, length - 1)) == true
      burnMem(output)

  test "PBKDF2-HMAC-SHA256 compile-time (1 iteration)":
    const
      check0 = pbkdf2(sha256, passwords256[0], salts256[0], 1, lengths256[0])

    let expect0 = fromHex(stripSpaces(expects256_1[0]))
    check:
      compare(toOpenArray(expect0, 0, lengths256[0] - 1),
              toOpenArray(check0, 0, lengths256[0] - 1)) == true

  when defined(release):
    test "PBKDF2-HMAC-SHA256 (100,000 iterations)":
      var ctx: HMAC[sha256]
      var output: array[128, byte]
      for i in 20..<len(lengths256):
        var index = i mod 10
        let p = stripSpaces(passwords256[index])
        let s = stripSpaces(salts256[index])
        let e = fromHex(stripSpaces(expects256_100k[index]))
        let length = lengths256[i]
        check:
          pbkdf2(ctx, p, s, 100000, output.toOpenArray(0, length - 1)) == length
          compare(toOpenArray(e, 0, length - 1),
                  toOpenArray(output, 0, length - 1)) == true
        burnMem(output)

  test "PBKDF2-HMAC-SHA384 (1 iteration)":
    var ctx: HMAC[sha384]
    var output: array[128, byte]
    for i in 0..<len(lengths384):
      var index = i mod 10
      let p = stripSpaces(passwords384[index])
      let s = stripSpaces(salts384[index])
      let e = fromHex(stripSpaces(expects384_1[index]))
      let length = lengths384[i]
      check pbkdf2(ctx, p, s, 1, output.toOpenArray(0, length - 1)) == length
      check:
        compare(toOpenArray(e, 0, length - 1),
                toOpenArray(output, 0, length - 1)) == true
      burnMem(output)

  test "PBKDF2-HMAC-SHA384 compile-time (1 iteration)":
    const
      check0 = pbkdf2(sha384, passwords384[0], salts384[0], 1, lengths384[0])

    let expect0 = fromHex(stripSpaces(expects384_1[0]))
    check:
      compare(toOpenArray(expect0, 0, lengths384[0] - 1),
              toOpenArray(check0, 0, lengths384[0] - 1)) == true

  when defined(release):
    test "PBKDF2-HMAC-SHA384 (100,000 iterations)":
      var ctx: HMAC[sha384]
      var output: array[128, byte]
      for i in 20..<len(lengths384):
        var index = i mod 10
        let p = stripSpaces(passwords384[index])
        let s = stripSpaces(salts384[index])
        let e = fromHex(stripSpaces(expects384_100k[index]))
        let length = lengths384[i]
        check pbkdf2(ctx, p, s, 100000,
              output.toOpenArray(0, length - 1)) == length
        check:
          compare(toOpenArray(e, 0, length - 1),
                  toOpenArray(output, 0, length - 1)) == true
        burnMem(output)

  test "PBKDF2-HMAC-SHA512 (1 iteration)":
    var ctx: HMAC[sha512]
    var output: array[128, byte]
    for i in 0..<len(lengths512):
      var index = i mod 10
      let p = stripSpaces(passwords512[index])
      let s = stripSpaces(salts512[index])
      let e = fromHex(stripSpaces(expects512_1[index]))
      let length = lengths512[i]
      check pbkdf2(ctx, p, s, 1, output.toOpenArray(0, length - 1)) == length
      check:
        compare(toOpenArray(e, 0, length - 1),
                toOpenArray(output, 0, length - 1)) == true
      burnMem(output)

  test "PBKDF2-HMAC-SHA512 compile-time (1 iteration)":
    const
      check0 = pbkdf2(sha512, passwords512[0], salts512[0], 1, lengths512[0])

    let expect0 = fromHex(stripSpaces(expects512_1[0]))
    check:
      compare(toOpenArray(expect0, 0, lengths512[0] - 1),
              toOpenArray(check0, 0, lengths512[0] - 1)) == true

  when defined(release):
    test "PBKDF2-HMAC-SHA512 (100,000 iterations)":
      var ctx: HMAC[sha512]
      var output: array[128, byte]
      for i in 20..<len(lengths512):
        var index = i mod 10
        let p = stripSpaces(passwords512[index])
        let s = stripSpaces(salts512[index])
        let e = fromHex(stripSpaces(expects512_100k[index]))
        let length = lengths512[i]
        check pbkdf2(ctx, p, s, 100000,
                     output.toOpenArray(0, length - 1)) == length
        check:
          compare(toOpenArray(e, 0, length - 1),
                  toOpenArray(output, 0, length - 1)) == true
        burnMem(output)
