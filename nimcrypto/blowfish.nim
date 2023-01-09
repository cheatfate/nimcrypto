#
#
#                    NimCrypto
#        (c) Copyright 2016 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements Blowfish crypto algorithm by Bruce Schneier
##
## Code based on `C implementation of the Blowfish algorithm` created by
## Paul Kocher [https://www.schneier.com/code/bfsh-koc.zip].
##
## Tests made according to official test vectors by Eric Young
## [https://www.schneier.com/code/vectors.txt] and adopted version by
## Randy L. Milbert [https://www.schneier.com/code/vectors2.txt], except
## chaining mode tests.
##
## Implementation was made with "blowfish bug" in mind
## [https://www.schneier.com/blowfish-bug.txt]
##
## Some warnings from Paul Kocher:
##
## Warning #1:  The code does not check key lengths. (Caveat encryptor.)
## Warning #2:  Beware that Blowfish keys repeat such that "ab" = "abab".
## Warning #3:  It is normally a good idea to zeroize the BLOWFISH_CTX before
## freeing it.
## Warning #4:  Endianness conversions are the responsibility of the caller.
## (To encrypt bytes on a little-endian platforms, you'll probably want
## to swap bytes around instead of just casting.)
## Warning #5:  Make sure to use a reasonable mode of operation for your
## application.  (If you don't know what CBC mode is, see Warning #7.)
## Warning #6:  This code is susceptible to timing attacks.
## Warning #7:  Security engineering is risky and non-intuitive.  Have someone
## check your work. If you don't know what you are doing, get help.

import utils

{.deadCodeElim:on.}

const
  N = 16

  ORIG_P = [ 0x243F6A88'u32, 0x85A308D3'u32, 0x13198A2E'u32, 0x03707344'u32,
             0xA4093822'u32, 0x299F31D0'u32, 0x082EFA98'u32, 0xEC4E6C89'u32,
             0x452821E6'u32, 0x38D01377'u32, 0xBE5466CF'u32, 0x34E90C6C'u32,
             0xC0AC29B7'u32, 0xC97C50DD'u32, 0x3F84D5B5'u32, 0xB5470917'u32,
             0x9216D5D9'u32, 0x8979FB1B'u32 ]
  ORIG_S = [
             [
               0xD1310BA6'u32, 0x98DFB5AC'u32, 0x2FFD72DB'u32, 0xD01ADFB7'u32,
               0xB8E1AFED'u32, 0x6A267E96'u32, 0xBA7C9045'u32, 0xF12C7F99'u32,
               0x24A19947'u32, 0xB3916CF7'u32, 0x0801F2E2'u32, 0x858EFC16'u32,
               0x636920D8'u32, 0x71574E69'u32, 0xA458FEA3'u32, 0xF4933D7E'u32,
               0x0D95748F'u32, 0x728EB658'u32, 0x718BCD58'u32, 0x82154AEE'u32,
               0x7B54A41D'u32, 0xC25A59B5'u32, 0x9C30D539'u32, 0x2AF26013'u32,
               0xC5D1B023'u32, 0x286085F0'u32, 0xCA417918'u32, 0xB8DB38EF'u32,
               0x8E79DCB0'u32, 0x603A180E'u32, 0x6C9E0E8B'u32, 0xB01E8A3E'u32,
               0xD71577C1'u32, 0xBD314B27'u32, 0x78AF2FDA'u32, 0x55605C60'u32,
               0xE65525F3'u32, 0xAA55AB94'u32, 0x57489862'u32, 0x63E81440'u32,
               0x55CA396A'u32, 0x2AAB10B6'u32, 0xB4CC5C34'u32, 0x1141E8CE'u32,
               0xA15486AF'u32, 0x7C72E993'u32, 0xB3EE1411'u32, 0x636FBC2A'u32,
               0x2BA9C55D'u32, 0x741831F6'u32, 0xCE5C3E16'u32, 0x9B87931E'u32,
               0xAFD6BA33'u32, 0x6C24CF5C'u32, 0x7A325381'u32, 0x28958677'u32,
               0x3B8F4898'u32, 0x6B4BB9AF'u32, 0xC4BFE81B'u32, 0x66282193'u32,
               0x61D809CC'u32, 0xFB21A991'u32, 0x487CAC60'u32, 0x5DEC8032'u32,
               0xEF845D5D'u32, 0xE98575B1'u32, 0xDC262302'u32, 0xEB651B88'u32,
               0x23893E81'u32, 0xD396ACC5'u32, 0x0F6D6FF3'u32, 0x83F44239'u32,
               0x2E0B4482'u32, 0xA4842004'u32, 0x69C8F04A'u32, 0x9E1F9B5E'u32,
               0x21C66842'u32, 0xF6E96C9A'u32, 0x670C9C61'u32, 0xABD388F0'u32,
               0x6A51A0D2'u32, 0xD8542F68'u32, 0x960FA728'u32, 0xAB5133A3'u32,
               0x6EEF0B6C'u32, 0x137A3BE4'u32, 0xBA3BF050'u32, 0x7EFB2A98'u32,
               0xA1F1651D'u32, 0x39AF0176'u32, 0x66CA593E'u32, 0x82430E88'u32,
               0x8CEE8619'u32, 0x456F9FB4'u32, 0x7D84A5C3'u32, 0x3B8B5EBE'u32,
               0xE06F75D8'u32, 0x85C12073'u32, 0x401A449F'u32, 0x56C16AA6'u32,
               0x4ED3AA62'u32, 0x363F7706'u32, 0x1BFEDF72'u32, 0x429B023D'u32,
               0x37D0D724'u32, 0xD00A1248'u32, 0xDB0FEAD3'u32, 0x49F1C09B'u32,
               0x075372C9'u32, 0x80991B7B'u32, 0x25D479D8'u32, 0xF6E8DEF7'u32,
               0xE3FE501A'u32, 0xB6794C3B'u32, 0x976CE0BD'u32, 0x04C006BA'u32,
               0xC1A94FB6'u32, 0x409F60C4'u32, 0x5E5C9EC2'u32, 0x196A2463'u32,
               0x68FB6FAF'u32, 0x3E6C53B5'u32, 0x1339B2EB'u32, 0x3B52EC6F'u32,
               0x6DFC511F'u32, 0x9B30952C'u32, 0xCC814544'u32, 0xAF5EBD09'u32,
               0xBEE3D004'u32, 0xDE334AFD'u32, 0x660F2807'u32, 0x192E4BB3'u32,
               0xC0CBA857'u32, 0x45C8740F'u32, 0xD20B5F39'u32, 0xB9D3FBDB'u32,
               0x5579C0BD'u32, 0x1A60320A'u32, 0xD6A100C6'u32, 0x402C7279'u32,
               0x679F25FE'u32, 0xFB1FA3CC'u32, 0x8EA5E9F8'u32, 0xDB3222F8'u32,
               0x3C7516DF'u32, 0xFD616B15'u32, 0x2F501EC8'u32, 0xAD0552AB'u32,
               0x323DB5FA'u32, 0xFD238760'u32, 0x53317B48'u32, 0x3E00DF82'u32,
               0x9E5C57BB'u32, 0xCA6F8CA0'u32, 0x1A87562E'u32, 0xDF1769DB'u32,
               0xD542A8F6'u32, 0x287EFFC3'u32, 0xAC6732C6'u32, 0x8C4F5573'u32,
               0x695B27B0'u32, 0xBBCA58C8'u32, 0xE1FFA35D'u32, 0xB8F011A0'u32,
               0x10FA3D98'u32, 0xFD2183B8'u32, 0x4AFCB56C'u32, 0x2DD1D35B'u32,
               0x9A53E479'u32, 0xB6F84565'u32, 0xD28E49BC'u32, 0x4BFB9790'u32,
               0xE1DDF2DA'u32, 0xA4CB7E33'u32, 0x62FB1341'u32, 0xCEE4C6E8'u32,
               0xEF20CADA'u32, 0x36774C01'u32, 0xD07E9EFE'u32, 0x2BF11FB4'u32,
               0x95DBDA4D'u32, 0xAE909198'u32, 0xEAAD8E71'u32, 0x6B93D5A0'u32,
               0xD08ED1D0'u32, 0xAFC725E0'u32, 0x8E3C5B2F'u32, 0x8E7594B7'u32,
               0x8FF6E2FB'u32, 0xF2122B64'u32, 0x8888B812'u32, 0x900DF01C'u32,
               0x4FAD5EA0'u32, 0x688FC31C'u32, 0xD1CFF191'u32, 0xB3A8C1AD'u32,
               0x2F2F2218'u32, 0xBE0E1777'u32, 0xEA752DFE'u32, 0x8B021FA1'u32,
               0xE5A0CC0F'u32, 0xB56F74E8'u32, 0x18ACF3D6'u32, 0xCE89E299'u32,
               0xB4A84FE0'u32, 0xFD13E0B7'u32, 0x7CC43B81'u32, 0xD2ADA8D9'u32,
               0x165FA266'u32, 0x80957705'u32, 0x93CC7314'u32, 0x211A1477'u32,
               0xE6AD2065'u32, 0x77B5FA86'u32, 0xC75442F5'u32, 0xFB9D35CF'u32,
               0xEBCDAF0C'u32, 0x7B3E89A0'u32, 0xD6411BD3'u32, 0xAE1E7E49'u32,
               0x00250E2D'u32, 0x2071B35E'u32, 0x226800BB'u32, 0x57B8E0AF'u32,
               0x2464369B'u32, 0xF009B91E'u32, 0x5563911D'u32, 0x59DFA6AA'u32,
               0x78C14389'u32, 0xD95A537F'u32, 0x207D5BA2'u32, 0x02E5B9C5'u32,
               0x83260376'u32, 0x6295CFA9'u32, 0x11C81968'u32, 0x4E734A41'u32,
               0xB3472DCA'u32, 0x7B14A94A'u32, 0x1B510052'u32, 0x9A532915'u32,
               0xD60F573F'u32, 0xBC9BC6E4'u32, 0x2B60A476'u32, 0x81E67400'u32,
               0x08BA6FB5'u32, 0x571BE91F'u32, 0xF296EC6B'u32, 0x2A0DD915'u32,
               0xB6636521'u32, 0xE7B9F9B6'u32, 0xFF34052E'u32, 0xC5855664'u32,
               0x53B02D5D'u32, 0xA99F8FA1'u32, 0x08BA4799'u32, 0x6E85076A'u32
             ],
             [
               0x4B7A70E9'u32, 0xB5B32944'u32, 0xDB75092E'u32, 0xC4192623'u32,
               0xAD6EA6B0'u32, 0x49A7DF7D'u32, 0x9CEE60B8'u32, 0x8FEDB266'u32,
               0xECAA8C71'u32, 0x699A17FF'u32, 0x5664526C'u32, 0xC2B19EE1'u32,
               0x193602A5'u32, 0x75094C29'u32, 0xA0591340'u32, 0xE4183A3E'u32,
               0x3F54989A'u32, 0x5B429D65'u32, 0x6B8FE4D6'u32, 0x99F73FD6'u32,
               0xA1D29C07'u32, 0xEFE830F5'u32, 0x4D2D38E6'u32, 0xF0255DC1'u32,
               0x4CDD2086'u32, 0x8470EB26'u32, 0x6382E9C6'u32, 0x021ECC5E'u32,
               0x09686B3F'u32, 0x3EBAEFC9'u32, 0x3C971814'u32, 0x6B6A70A1'u32,
               0x687F3584'u32, 0x52A0E286'u32, 0xB79C5305'u32, 0xAA500737'u32,
               0x3E07841C'u32, 0x7FDEAE5C'u32, 0x8E7D44EC'u32, 0x5716F2B8'u32,
               0xB03ADA37'u32, 0xF0500C0D'u32, 0xF01C1F04'u32, 0x0200B3FF'u32,
               0xAE0CF51A'u32, 0x3CB574B2'u32, 0x25837A58'u32, 0xDC0921BD'u32,
               0xD19113F9'u32, 0x7CA92FF6'u32, 0x94324773'u32, 0x22F54701'u32,
               0x3AE5E581'u32, 0x37C2DADC'u32, 0xC8B57634'u32, 0x9AF3DDA7'u32,
               0xA9446146'u32, 0x0FD0030E'u32, 0xECC8C73E'u32, 0xA4751E41'u32,
               0xE238CD99'u32, 0x3BEA0E2F'u32, 0x3280BBA1'u32, 0x183EB331'u32,
               0x4E548B38'u32, 0x4F6DB908'u32, 0x6F420D03'u32, 0xF60A04BF'u32,
               0x2CB81290'u32, 0x24977C79'u32, 0x5679B072'u32, 0xBCAF89AF'u32,
               0xDE9A771F'u32, 0xD9930810'u32, 0xB38BAE12'u32, 0xDCCF3F2E'u32,
               0x5512721F'u32, 0x2E6B7124'u32, 0x501ADDE6'u32, 0x9F84CD87'u32,
               0x7A584718'u32, 0x7408DA17'u32, 0xBC9F9ABC'u32, 0xE94B7D8C'u32,
               0xEC7AEC3A'u32, 0xDB851DFA'u32, 0x63094366'u32, 0xC464C3D2'u32,
               0xEF1C1847'u32, 0x3215D908'u32, 0xDD433B37'u32, 0x24C2BA16'u32,
               0x12A14D43'u32, 0x2A65C451'u32, 0x50940002'u32, 0x133AE4DD'u32,
               0x71DFF89E'u32, 0x10314E55'u32, 0x81AC77D6'u32, 0x5F11199B'u32,
               0x043556F1'u32, 0xD7A3C76B'u32, 0x3C11183B'u32, 0x5924A509'u32,
               0xF28FE6ED'u32, 0x97F1FBFA'u32, 0x9EBABF2C'u32, 0x1E153C6E'u32,
               0x86E34570'u32, 0xEAE96FB1'u32, 0x860E5E0A'u32, 0x5A3E2AB3'u32,
               0x771FE71C'u32, 0x4E3D06FA'u32, 0x2965DCB9'u32, 0x99E71D0F'u32,
               0x803E89D6'u32, 0x5266C825'u32, 0x2E4CC978'u32, 0x9C10B36A'u32,
               0xC6150EBA'u32, 0x94E2EA78'u32, 0xA5FC3C53'u32, 0x1E0A2DF4'u32,
               0xF2F74EA7'u32, 0x361D2B3D'u32, 0x1939260F'u32, 0x19C27960'u32,
               0x5223A708'u32, 0xF71312B6'u32, 0xEBADFE6E'u32, 0xEAC31F66'u32,
               0xE3BC4595'u32, 0xA67BC883'u32, 0xB17F37D1'u32, 0x018CFF28'u32,
               0xC332DDEF'u32, 0xBE6C5AA5'u32, 0x65582185'u32, 0x68AB9802'u32,
               0xEECEA50F'u32, 0xDB2F953B'u32, 0x2AEF7DAD'u32, 0x5B6E2F84'u32,
               0x1521B628'u32, 0x29076170'u32, 0xECDD4775'u32, 0x619F1510'u32,
               0x13CCA830'u32, 0xEB61BD96'u32, 0x0334FE1E'u32, 0xAA0363CF'u32,
               0xB5735C90'u32, 0x4C70A239'u32, 0xD59E9E0B'u32, 0xCBAADE14'u32,
               0xEECC86BC'u32, 0x60622CA7'u32, 0x9CAB5CAB'u32, 0xB2F3846E'u32,
               0x648B1EAF'u32, 0x19BDF0CA'u32, 0xA02369B9'u32, 0x655ABB50'u32,
               0x40685A32'u32, 0x3C2AB4B3'u32, 0x319EE9D5'u32, 0xC021B8F7'u32,
               0x9B540B19'u32, 0x875FA099'u32, 0x95F7997E'u32, 0x623D7DA8'u32,
               0xF837889A'u32, 0x97E32D77'u32, 0x11ED935F'u32, 0x16681281'u32,
               0x0E358829'u32, 0xC7E61FD6'u32, 0x96DEDFA1'u32, 0x7858BA99'u32,
               0x57F584A5'u32, 0x1B227263'u32, 0x9B83C3FF'u32, 0x1AC24696'u32,
               0xCDB30AEB'u32, 0x532E3054'u32, 0x8FD948E4'u32, 0x6DBC3128'u32,
               0x58EBF2EF'u32, 0x34C6FFEA'u32, 0xFE28ED61'u32, 0xEE7C3C73'u32,
               0x5D4A14D9'u32, 0xE864B7E3'u32, 0x42105D14'u32, 0x203E13E0'u32,
               0x45EEE2B6'u32, 0xA3AAABEA'u32, 0xDB6C4F15'u32, 0xFACB4FD0'u32,
               0xC742F442'u32, 0xEF6ABBB5'u32, 0x654F3B1D'u32, 0x41CD2105'u32,
               0xD81E799E'u32, 0x86854DC7'u32, 0xE44B476A'u32, 0x3D816250'u32,
               0xCF62A1F2'u32, 0x5B8D2646'u32, 0xFC8883A0'u32, 0xC1C7B6A3'u32,
               0x7F1524C3'u32, 0x69CB7492'u32, 0x47848A0B'u32, 0x5692B285'u32,
               0x095BBF00'u32, 0xAD19489D'u32, 0x1462B174'u32, 0x23820E00'u32,
               0x58428D2A'u32, 0x0C55F5EA'u32, 0x1DADF43E'u32, 0x233F7061'u32,
               0x3372F092'u32, 0x8D937E41'u32, 0xD65FECF1'u32, 0x6C223BDB'u32,
               0x7CDE3759'u32, 0xCBEE7460'u32, 0x4085F2A7'u32, 0xCE77326E'u32,
               0xA6078084'u32, 0x19F8509E'u32, 0xE8EFD855'u32, 0x61D99735'u32,
               0xA969A7AA'u32, 0xC50C06C2'u32, 0x5A04ABFC'u32, 0x800BCADC'u32,
               0x9E447A2E'u32, 0xC3453484'u32, 0xFDD56705'u32, 0x0E1E9EC9'u32,
               0xDB73DBD3'u32, 0x105588CD'u32, 0x675FDA79'u32, 0xE3674340'u32,
               0xC5C43465'u32, 0x713E38D8'u32, 0x3D28F89E'u32, 0xF16DFF20'u32,
               0x153E21E7'u32, 0x8FB03D4A'u32, 0xE6E39F2B'u32, 0xDB83ADF7'u32
             ],
             [
               0xE93D5A68'u32, 0x948140F7'u32, 0xF64C261C'u32, 0x94692934'u32,
               0x411520F7'u32, 0x7602D4F7'u32, 0xBCF46B2E'u32, 0xD4A20068'u32,
               0xD4082471'u32, 0x3320F46A'u32, 0x43B7D4B7'u32, 0x500061AF'u32,
               0x1E39F62E'u32, 0x97244546'u32, 0x14214F74'u32, 0xBF8B8840'u32,
               0x4D95FC1D'u32, 0x96B591AF'u32, 0x70F4DDD3'u32, 0x66A02F45'u32,
               0xBFBC09EC'u32, 0x03BD9785'u32, 0x7FAC6DD0'u32, 0x31CB8504'u32,
               0x96EB27B3'u32, 0x55FD3941'u32, 0xDA2547E6'u32, 0xABCA0A9A'u32,
               0x28507825'u32, 0x530429F4'u32, 0x0A2C86DA'u32, 0xE9B66DFB'u32,
               0x68DC1462'u32, 0xD7486900'u32, 0x680EC0A4'u32, 0x27A18DEE'u32,
               0x4F3FFEA2'u32, 0xE887AD8C'u32, 0xB58CE006'u32, 0x7AF4D6B6'u32,
               0xAACE1E7C'u32, 0xD3375FEC'u32, 0xCE78A399'u32, 0x406B2A42'u32,
               0x20FE9E35'u32, 0xD9F385B9'u32, 0xEE39D7AB'u32, 0x3B124E8B'u32,
               0x1DC9FAF7'u32, 0x4B6D1856'u32, 0x26A36631'u32, 0xEAE397B2'u32,
               0x3A6EFA74'u32, 0xDD5B4332'u32, 0x6841E7F7'u32, 0xCA7820FB'u32,
               0xFB0AF54E'u32, 0xD8FEB397'u32, 0x454056AC'u32, 0xBA489527'u32,
               0x55533A3A'u32, 0x20838D87'u32, 0xFE6BA9B7'u32, 0xD096954B'u32,
               0x55A867BC'u32, 0xA1159A58'u32, 0xCCA92963'u32, 0x99E1DB33'u32,
               0xA62A4A56'u32, 0x3F3125F9'u32, 0x5EF47E1C'u32, 0x9029317C'u32,
               0xFDF8E802'u32, 0x04272F70'u32, 0x80BB155C'u32, 0x05282CE3'u32,
               0x95C11548'u32, 0xE4C66D22'u32, 0x48C1133F'u32, 0xC70F86DC'u32,
               0x07F9C9EE'u32, 0x41041F0F'u32, 0x404779A4'u32, 0x5D886E17'u32,
               0x325F51EB'u32, 0xD59BC0D1'u32, 0xF2BCC18F'u32, 0x41113564'u32,
               0x257B7834'u32, 0x602A9C60'u32, 0xDFF8E8A3'u32, 0x1F636C1B'u32,
               0x0E12B4C2'u32, 0x02E1329E'u32, 0xAF664FD1'u32, 0xCAD18115'u32,
               0x6B2395E0'u32, 0x333E92E1'u32, 0x3B240B62'u32, 0xEEBEB922'u32,
               0x85B2A20E'u32, 0xE6BA0D99'u32, 0xDE720C8C'u32, 0x2DA2F728'u32,
               0xD0127845'u32, 0x95B794FD'u32, 0x647D0862'u32, 0xE7CCF5F0'u32,
               0x5449A36F'u32, 0x877D48FA'u32, 0xC39DFD27'u32, 0xF33E8D1E'u32,
               0x0A476341'u32, 0x992EFF74'u32, 0x3A6F6EAB'u32, 0xF4F8FD37'u32,
               0xA812DC60'u32, 0xA1EBDDF8'u32, 0x991BE14C'u32, 0xDB6E6B0D'u32,
               0xC67B5510'u32, 0x6D672C37'u32, 0x2765D43B'u32, 0xDCD0E804'u32,
               0xF1290DC7'u32, 0xCC00FFA3'u32, 0xB5390F92'u32, 0x690FED0B'u32,
               0x667B9FFB'u32, 0xCEDB7D9C'u32, 0xA091CF0B'u32, 0xD9155EA3'u32,
               0xBB132F88'u32, 0x515BAD24'u32, 0x7B9479BF'u32, 0x763BD6EB'u32,
               0x37392EB3'u32, 0xCC115979'u32, 0x8026E297'u32, 0xF42E312D'u32,
               0x6842ADA7'u32, 0xC66A2B3B'u32, 0x12754CCC'u32, 0x782EF11C'u32,
               0x6A124237'u32, 0xB79251E7'u32, 0x06A1BBE6'u32, 0x4BFB6350'u32,
               0x1A6B1018'u32, 0x11CAEDFA'u32, 0x3D25BDD8'u32, 0xE2E1C3C9'u32,
               0x44421659'u32, 0x0A121386'u32, 0xD90CEC6E'u32, 0xD5ABEA2A'u32,
               0x64AF674E'u32, 0xDA86A85F'u32, 0xBEBFE988'u32, 0x64E4C3FE'u32,
               0x9DBC8057'u32, 0xF0F7C086'u32, 0x60787BF8'u32, 0x6003604D'u32,
               0xD1FD8346'u32, 0xF6381FB0'u32, 0x7745AE04'u32, 0xD736FCCC'u32,
               0x83426B33'u32, 0xF01EAB71'u32, 0xB0804187'u32, 0x3C005E5F'u32,
               0x77A057BE'u32, 0xBDE8AE24'u32, 0x55464299'u32, 0xBF582E61'u32,
               0x4E58F48F'u32, 0xF2DDFDA2'u32, 0xF474EF38'u32, 0x8789BDC2'u32,
               0x5366F9C3'u32, 0xC8B38E74'u32, 0xB475F255'u32, 0x46FCD9B9'u32,
               0x7AEB2661'u32, 0x8B1DDF84'u32, 0x846A0E79'u32, 0x915F95E2'u32,
               0x466E598E'u32, 0x20B45770'u32, 0x8CD55591'u32, 0xC902DE4C'u32,
               0xB90BACE1'u32, 0xBB8205D0'u32, 0x11A86248'u32, 0x7574A99E'u32,
               0xB77F19B6'u32, 0xE0A9DC09'u32, 0x662D09A1'u32, 0xC4324633'u32,
               0xE85A1F02'u32, 0x09F0BE8C'u32, 0x4A99A025'u32, 0x1D6EFE10'u32,
               0x1AB93D1D'u32, 0x0BA5A4DF'u32, 0xA186F20F'u32, 0x2868F169'u32,
               0xDCB7DA83'u32, 0x573906FE'u32, 0xA1E2CE9B'u32, 0x4FCD7F52'u32,
               0x50115E01'u32, 0xA70683FA'u32, 0xA002B5C4'u32, 0x0DE6D027'u32,
               0x9AF88C27'u32, 0x773F8641'u32, 0xC3604C06'u32, 0x61A806B5'u32,
               0xF0177A28'u32, 0xC0F586E0'u32, 0x006058AA'u32, 0x30DC7D62'u32,
               0x11E69ED7'u32, 0x2338EA63'u32, 0x53C2DD94'u32, 0xC2C21634'u32,
               0xBBCBEE56'u32, 0x90BCB6DE'u32, 0xEBFC7DA1'u32, 0xCE591D76'u32,
               0x6F05E409'u32, 0x4B7C0188'u32, 0x39720A3D'u32, 0x7C927C24'u32,
               0x86E3725F'u32, 0x724D9DB9'u32, 0x1AC15BB4'u32, 0xD39EB8FC'u32,
               0xED545578'u32, 0x08FCA5B5'u32, 0xD83D7CD3'u32, 0x4DAD0FC4'u32,
               0x1E50EF5E'u32, 0xB161E6F8'u32, 0xA28514D9'u32, 0x6C51133C'u32,
               0x6FD5C7E7'u32, 0x56E14EC4'u32, 0x362ABFCE'u32, 0xDDC6C837'u32,
               0xD79A3234'u32, 0x92638212'u32, 0x670EFA8E'u32, 0x406000E0'u32
             ],
             [
               0x3A39CE37'u32, 0xD3FAF5CF'u32, 0xABC27737'u32, 0x5AC52D1B'u32,
               0x5CB0679E'u32, 0x4FA33742'u32, 0xD3822740'u32, 0x99BC9BBE'u32,
               0xD5118E9D'u32, 0xBF0F7315'u32, 0xD62D1C7E'u32, 0xC700C47B'u32,
               0xB78C1B6B'u32, 0x21A19045'u32, 0xB26EB1BE'u32, 0x6A366EB4'u32,
               0x5748AB2F'u32, 0xBC946E79'u32, 0xC6A376D2'u32, 0x6549C2C8'u32,
               0x530FF8EE'u32, 0x468DDE7D'u32, 0xD5730A1D'u32, 0x4CD04DC6'u32,
               0x2939BBDB'u32, 0xA9BA4650'u32, 0xAC9526E8'u32, 0xBE5EE304'u32,
               0xA1FAD5F0'u32, 0x6A2D519A'u32, 0x63EF8CE2'u32, 0x9A86EE22'u32,
               0xC089C2B8'u32, 0x43242EF6'u32, 0xA51E03AA'u32, 0x9CF2D0A4'u32,
               0x83C061BA'u32, 0x9BE96A4D'u32, 0x8FE51550'u32, 0xBA645BD6'u32,
               0x2826A2F9'u32, 0xA73A3AE1'u32, 0x4BA99586'u32, 0xEF5562E9'u32,
               0xC72FEFD3'u32, 0xF752F7DA'u32, 0x3F046F69'u32, 0x77FA0A59'u32,
               0x80E4A915'u32, 0x87B08601'u32, 0x9B09E6AD'u32, 0x3B3EE593'u32,
               0xE990FD5A'u32, 0x9E34D797'u32, 0x2CF0B7D9'u32, 0x022B8B51'u32,
               0x96D5AC3A'u32, 0x017DA67D'u32, 0xD1CF3ED6'u32, 0x7C7D2D28'u32,
               0x1F9F25CF'u32, 0xADF2B89B'u32, 0x5AD6B472'u32, 0x5A88F54C'u32,
               0xE029AC71'u32, 0xE019A5E6'u32, 0x47B0ACFD'u32, 0xED93FA9B'u32,
               0xE8D3C48D'u32, 0x283B57CC'u32, 0xF8D56629'u32, 0x79132E28'u32,
               0x785F0191'u32, 0xED756055'u32, 0xF7960E44'u32, 0xE3D35E8C'u32,
               0x15056DD4'u32, 0x88F46DBA'u32, 0x03A16125'u32, 0x0564F0BD'u32,
               0xC3EB9E15'u32, 0x3C9057A2'u32, 0x97271AEC'u32, 0xA93A072A'u32,
               0x1B3F6D9B'u32, 0x1E6321F5'u32, 0xF59C66FB'u32, 0x26DCF319'u32,
               0x7533D928'u32, 0xB155FDF5'u32, 0x03563482'u32, 0x8ABA3CBB'u32,
               0x28517711'u32, 0xC20AD9F8'u32, 0xABCC5167'u32, 0xCCAD925F'u32,
               0x4DE81751'u32, 0x3830DC8E'u32, 0x379D5862'u32, 0x9320F991'u32,
               0xEA7A90C2'u32, 0xFB3E7BCE'u32, 0x5121CE64'u32, 0x774FBE32'u32,
               0xA8B6E37E'u32, 0xC3293D46'u32, 0x48DE5369'u32, 0x6413E680'u32,
               0xA2AE0810'u32, 0xDD6DB224'u32, 0x69852DFD'u32, 0x09072166'u32,
               0xB39A460A'u32, 0x6445C0DD'u32, 0x586CDECF'u32, 0x1C20C8AE'u32,
               0x5BBEF7DD'u32, 0x1B588D40'u32, 0xCCD2017F'u32, 0x6BB4E3BB'u32,
               0xDDA26A7E'u32, 0x3A59FF45'u32, 0x3E350A44'u32, 0xBCB4CDD5'u32,
               0x72EACEA8'u32, 0xFA6484BB'u32, 0x8D6612AE'u32, 0xBF3C6F47'u32,
               0xD29BE463'u32, 0x542F5D9E'u32, 0xAEC2771B'u32, 0xF64E6370'u32,
               0x740E0D8D'u32, 0xE75B1357'u32, 0xF8721671'u32, 0xAF537D5D'u32,
               0x4040CB08'u32, 0x4EB4E2CC'u32, 0x34D2466A'u32, 0x0115AF84'u32,
               0xE1B00428'u32, 0x95983A1D'u32, 0x06B89FB4'u32, 0xCE6EA048'u32,
               0x6F3F3B82'u32, 0x3520AB82'u32, 0x011A1D4B'u32, 0x277227F8'u32,
               0x611560B1'u32, 0xE7933FDC'u32, 0xBB3A792B'u32, 0x344525BD'u32,
               0xA08839E1'u32, 0x51CE794B'u32, 0x2F32C9B7'u32, 0xA01FBAC9'u32,
               0xE01CC87E'u32, 0xBCC7D1F6'u32, 0xCF0111C3'u32, 0xA1E8AAC7'u32,
               0x1A908749'u32, 0xD44FBD9A'u32, 0xD0DADECB'u32, 0xD50ADA38'u32,
               0x0339C32A'u32, 0xC6913667'u32, 0x8DF9317C'u32, 0xE0B12B4F'u32,
               0xF79E59B7'u32, 0x43F5BB3A'u32, 0xF2D519FF'u32, 0x27D9459C'u32,
               0xBF97222C'u32, 0x15E6FC2A'u32, 0x0F91FC71'u32, 0x9B941525'u32,
               0xFAE59361'u32, 0xCEB69CEB'u32, 0xC2A86459'u32, 0x12BAA8D1'u32,
               0xB6C1075E'u32, 0xE3056A0C'u32, 0x10D25065'u32, 0xCB03A442'u32,
               0xE0EC6E0E'u32, 0x1698DB3B'u32, 0x4C98A0BE'u32, 0x3278E964'u32,
               0x9F1F9532'u32, 0xE0D392DF'u32, 0xD3A0342B'u32, 0x8971F21E'u32,
               0x1B0A7441'u32, 0x4BA3348C'u32, 0xC5BE7120'u32, 0xC37632D8'u32,
               0xDF359F8D'u32, 0x9B992F2E'u32, 0xE60B6F47'u32, 0x0FE3F11D'u32,
               0xE54CDA54'u32, 0x1EDAD891'u32, 0xCE6279CF'u32, 0xCD3E7E6F'u32,
               0x1618B166'u32, 0xFD2C1D05'u32, 0x848FD2C5'u32, 0xF6FB2299'u32,
               0xF523F357'u32, 0xA6327623'u32, 0x93A83531'u32, 0x56CCCD02'u32,
               0xACF08162'u32, 0x5A75EBB5'u32, 0x6E163697'u32, 0x88D273CC'u32,
               0xDE966292'u32, 0x81B949D0'u32, 0x4C50901B'u32, 0x71C65614'u32,
               0xE6C6C7BD'u32, 0x327A140A'u32, 0x45E1D006'u32, 0xC3F27B9A'u32,
               0xC9AA53FD'u32, 0x62A80F00'u32, 0xBB25BFE2'u32, 0x35BDD2F6'u32,
               0x71126905'u32, 0xB2040222'u32, 0xB6CBCF7C'u32, 0xCD769C2B'u32,
               0x53113EC0'u32, 0x1640E3D3'u32, 0x38ABBD60'u32, 0x2547ADF0'u32,
               0xBA38209C'u32, 0xF746CE76'u32, 0x77AFA1C5'u32, 0x20756060'u32,
               0x85CBFE4E'u32, 0x8AE88DD8'u32, 0x7AAAF9B0'u32, 0x4CF9AA7E'u32,
               0x1948C25C'u32, 0x02FB8A8C'u32, 0x01C36AE4'u32, 0xD6EBE1F9'u32,
               0x90D4F869'u32, 0xA65CDEA0'u32, 0x3F09252D'u32, 0xC208E69F'u32,
               0xB74E6132'u32, 0xCE77E25B'u32, 0x578FDFE3'u32, 0x3AC372E6'u32
             ]
           ]

type
  BlowfishContext[bits: static[uint]] = object
    sizeKey: int
    P: array[16 + 2, uint32]
    S: array[4, array[256, uint32]]

  blowfish* = BlowfishContext[64]

template f(ctx: var BlowfishContext, x: uint32): uint32 =
  var vx = x
  var d = cast[uint16](vx and 0xFF'u32)
  vx = vx shr 8
  var c = cast[uint16](vx and 0xFF'u32)
  vx = vx shr 8
  var b = cast[uint16](vx and 0xFF'u32)
  vx = vx shr 8
  var a = cast[uint16](vx and 0xFF'u32)
  var vy = ctx.S[0][a] + ctx.S[1][b]
  vy = vy xor ctx.S[2][c]
  vy = vy + ctx.S[3][d]
  vy

proc blowfishEncrypt*(ctx: var BlowfishContext, inp: openArray[byte],
                      oup: var openArray[byte]) =
  var nxl = leLoad32(inp, 0)
  var nxr = leLoad32(inp, 4)

  var temp = 0'u32
  var i = 0'i16

  while i < N:
    nxl = nxl xor ctx.P[i]
    nxr = f(ctx, nxl) xor nxr
    temp = nxl
    nxl = nxr
    nxr = temp
    inc(i)

  temp = nxl
  nxl = nxr
  nxr = temp

  nxr = nxr xor ctx.P[N]
  nxl = nxl xor ctx.P[N + 1]

  leStore32(oup, 0, nxl)
  leStore32(oup, 4, nxr)

proc blowfishDecrypt*(ctx: var BlowfishContext, inp: openArray[byte],
                      oup: var openArray[byte]) =

  var nxl = leLoad32(inp, 0)
  var nxr = leLoad32(inp, 4)
  var temp = 0'u32

  var i = N + 1
  while i > 1:
    nxl = nxl xor ctx.P[i]
    nxr = f(ctx, nxl) xor nxr
    temp = nxl
    nxl = nxr
    nxr = temp
    dec(i)

  temp = nxl
  nxl = nxr
  nxr = temp

  nxr = nxr xor ctx.P[1]
  nxl = nxl xor ctx.P[0]

  leStore32(oup, 0, nxl)
  leStore32(oup, 4, nxr)

proc initBlowfishContext*(ctx: var BlowfishContext, key: openArray[byte],
                          nkey: int) =
  var i = 0
  var j = 0
  var k = 0
  var data = 0'u32
  var length = nkey div 8

  while i < 4:
    j = 0
    while j < 256:
      ctx.S[i][j] = ORIG_S[i][j]
      inc(j)
    inc(i)

  j = 0
  i = 0
  while i < N + 2:
    data = 0
    k = 0
    while k < 4:
      data = data shl 8
      data = data or (key[j] and 0xFF)
      inc(j)
      if j >= length:
        j = 0
      inc(k)
    ctx.P[i] = ORIG_P[i] xor data
    inc(i)

  i = 0
  var datarl = [0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8, 0'u8]
  while i < N + 2:
    blowfishEncrypt(ctx, datarl, datarl)
    ctx.P[i] = leLoad32(datarl, 0)
    ctx.P[i + 1] = leLoad32(datarl, 4)
    i = i + 2

  i = 0
  while i < 4:
    j = 0
    while j < 256:
      blowfishEncrypt(ctx, datarl, datarl)
      ctx.S[i][j] = leLoad32(datarl, 0)
      ctx.S[i][j + 1] = leLoad32(datarl, 4)
      j = j + 2
    inc(i)

template sizeKey*(ctx: BlowfishContext): int =
  (ctx.sizeKey shr 3)

template sizeBlock*(ctx: BlowfishContext): int =
  (8)

template sizeKey*(r: typedesc[blowfish]): int =
  {.error: "Could not obtain key size of Blowfish cipher at compile-time".}

template sizeBlock*(r: typedesc[blowfish]): int =
  (8)

proc init*(ctx: var BlowfishContext, key: openArray[byte]) {.inline.} =
  ctx.sizeKey = len(key) shl 3
  initBlowfishContext(ctx, key, ctx.sizeKey)

proc init*(ctx: var BlowfishContext, key: ptr byte, nkey: int) {.inline.} =
  ctx.sizeKey = nkey shl 3
  var p = cast[ptr UncheckedArray[byte]](key)
  initBlowfishContext(ctx, toOpenArray(p, 0, (nkey shl 3) - 1),
                      ctx.sizeKey)

proc clear*(ctx: var BlowfishContext) {.inline.} =
  burnMem(ctx)

proc encrypt*(ctx: var BlowfishContext, input: openArray[byte],
              output: var openArray[byte]) {.inline.} =
  blowfishEncrypt(ctx, input, output)

proc decrypt*(ctx: var BlowfishContext, input: openArray[byte],
              output: var openArray[byte]) {.inline.} =
  blowfishDecrypt(ctx, input, output)

proc encrypt*(ctx: var BlowfishContext, inbytes: ptr byte,
              outbytes: ptr byte) {.inline.} =
  var ip = cast[ptr UncheckedArray[byte]](inbytes)
  var op = cast[ptr UncheckedArray[byte]](outbytes)
  blowfishEncrypt(ctx, toOpenArray(ip, 0, ctx.sizeBlock() - 1),
                       toOpenArray(op, 0, ctx.sizeBlock() - 1))

proc decrypt*(ctx: var BlowfishContext, inbytes: ptr byte,
              outbytes: ptr byte) {.inline.} =
  var ip = cast[ptr UncheckedArray[byte]](inbytes)
  var op = cast[ptr UncheckedArray[byte]](outbytes)
  blowfishDecrypt(ctx, toOpenArray(ip, 0, ctx.sizeBlock() - 1),
                       toOpenArray(op, 0, ctx.sizeBlock() - 1))
