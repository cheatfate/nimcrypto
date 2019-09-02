import nimcrypto/rijndael, nimcrypto/utils
import unittest

when defined(nimHasUsed): {.used.}

## Tests made according to official test vectors (Appendix B and Appendix C)
## [http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf].

suite "Rijndael/AES Tests":

  const
    testsP128 = [
      "f34481ec3cc627bacd5dc3fb08f273e6", "9798c4640bad75c7c3227db910174e72",
      "96ab5c2ff612d9dfaae8c31f30c42168", "6a118a874519e64e9963798a503f1d35",
      "cb9fceec81286ca3e989bd979b0cb284", "b26aeb1874e47ca8358ff22378f09144",
      "58c8e00b2631686d54eab84b91f0aca1",
    ]
    testsE128 = [
      "0336763e966d92595a567cc9ce537f5e", "a9a1631bf4996954ebc093957b234589",
      "ff4f8391a6a40ca5b25d23bedd44a597", "dc43be40be0e53712f7e2bf5ca707209",
      "92beedab1895a94faa69b632e5cc47ce", "459264f4798f6a78bacb89c15ed3d601",
      "08a4e2efec8a8e3312ca7460b9040bbf"
    ]
    testsP192 = [
      "1b077a6af4b7f98229de786d7516b639", "9c2d8842e5f48f57648205d39a239af1",
      "bff52510095f518ecca60af4205444bb", "51719783d3185a535bd75adc65071ce1",
      "26aa49dcfe7629a8901a69a9914e6dfd", "941a4773058224e1ef66d10e0a6ee782"
    ]
    testsE192 = [
      "275cfc0413d8ccb70513c3859b1d0f72", "c9b8135ff1b5adc413dfd053b21bd96d",
      "4a3650c3371ce2eb35e389a171427440", "4f354592ff7c8847d2d0870ca9481b7c",
      "d5e08bf9a182e857cf40b3a36ee248cc", "067cd9d3749207791841562507fa9626"
    ]
    testsP256 = [
      "014730f80ac625fe84f026c60bfd547d", "0b24af36193ce4665f2825d7b4749c98",
      "761c1fe41a18acf20d241650611d90f1", "8a560769d605868ad80d819bdba03771",
      "91fbef2d15a97816060bee1feaa49afe"
    ]
    testsE256 = [
      "5c9d844ed46f9885085e5d6a4f94c7d7", "a9ff75bd7cf6613d3731c77c3b6d0c04",
      "623a52fcea5d443e48d9181ab32c7421", "38f2c7ae10612415d27ca190d27da8b4",
      "1bc704f1bce135ceb810341b216d7abe"
    ]
    testsK128 = [
      "10a58869d74be5a374cf867cfb473859", "caea65cdbb75e9169ecd22ebe6e54675",
      "a2e2fa9baf7d20822ca9f0542f764a41", "b6364ac4e1de1e285eaf144a2415f7a0",
      "64cf9c7abc50b888af65f49d521944b2", "47d6742eefcc0465dc96355e851b64d9",
      "3eb39790678c56bee34bbcdeccf6cdb5", "64110a924f0743d500ccadae72c13427",
      "18d8126516f8a12ab1a36d9f04d68e51", "f530357968578480b398a3c251cd1093",
      "da84367f325d42d601b4326964802e8e", "e37b1c6aa2846f6fdb413f238b089f23",
      "6c002b682483e0cabcc731c253be5674", "143ae8ed6555aba96110ab58893a8ae1",
      "b69418a85332240dc82492353956ae0c", "71b5c08a1993e1362e4d0ce9b22b78d5",
      "e234cdca2606b81f29408d5f6da21206", "13237c49074a3da078dc1d828bb78c6f",
      "3071a2a48fe6cbd04f1a129098e308f8", "90f42ec0f68385f2ffc5dfc03a654dce",
      "febd9a24d8b65c1c787d50a4ed3619a9"
    ]
    testsC128 =[
      "6d251e6944b051e04eaa6fb4dbf78465", "6e29201190152df4ee058139def610bb",
      "c3b44b95d9d2f25670eee9a0de099fa3", "5d9b05578fc944b3cf1ccf0e746cd581",
      "f7efc89d5dba578104016ce5ad659c05", "0306194f666d183624aa230a8b264ae7",
      "858075d536d79ccee571f7d7204b1f67", "35870c6a57e9e92314bcb8087cde72ce",
      "6c68e9be5ec41e22c825b7c7affb4363", "f5df39990fc688f1b07224cc03e86cea",
      "bba071bcb470f8f6586e5d3add18bc66", "43c9f7e62f5d288bb27aa40ef8fe1ea8",
      "3580d19cff44f1014a7c966a69059de5", "806da864dd29d48deafbe764f8202aef",
      "a303d940ded8f0baff6f75414cac5243", "c2dabd117f8a3ecabfbb11d12194d9d0",
      "fff60a4740086b3b9c56195b98d91a7b", "8146a08e2357f0caa30ca8c94d1a0544",
      "4b98e06d356deb07ebb824e5713f7be3", "7a20a53d460fc9ce0423a7a0764c6cf2",
      "f4a70d8af877f9b02b4c40df57d45b17"
    ]
    testsK192 = [
      "e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd",
      "15d20f6ebc7e649fd95b76b107e6daba967c8a9484797f29",
      "a8a282ee31c03fae4f8e9b8930d5473c2ed695a347e88b7c",
      "cd62376d5ebb414917f0c78f05266433dc9192a1ec943300",
      "502a6ab36984af268bf423c7f509205207fc1552af4a91e5",
      "25a39dbfd8034f71a81f9ceb55026e4037f8f6aa30ab44ce",
      "e08c15411774ec4a908b64eadc6ac4199c7cd453f3aaef53",
      "3b375a1ff7e8d44409696e6326ec9dec86138e2ae010b980",
      "950bb9f22cc35be6fe79f52c320af93dec5bc9c0c2f9cd53",
      "7001c487cc3e572cfc92f4d0e697d982e8856fdcc957da40",
      "f029ce61d4e5a405b41ead0a883cc6a737da2cf50a6c92ae",
      "61257134a518a0d57d9d244d45f6498cbc32f2bafc522d79",
      "b0ab0a6a818baef2d11fa33eac947284fb7d748cfb75e570",
      "ee053aa011c8b428cdcc3636313c54d6a03cac01c71579d6",
      "d2926527e0aa9f37b45e2ec2ade5853ef807576104c7ace3",
      "982215f4e173dfa0fcffe5d3da41c4812c7bcc8ed3540f93",
      "98c6b8e01e379fbd14e61af6af891596583565f2a27d59e9",
      "b3ad5cea1dddc214ca969ac35f37dae1a9a9d1528f89bb35",
      "45899367c3132849763073c435a9288a766c8b9ec2308516",
      "ec250e04c3903f602647b85a401a1ae7ca2f02f67fa4253e",
      "d077a03bd8a38973928ccafe4a9d2f455130bd0af5ae46a9",
      "d184c36cf0dddfec39e654195006022237871a47c33d3198",
      "4c6994ffa9dcdc805b60c2c0095334c42d95a8fc0ca5b080",
      "c88f5b00a4ef9a6840e2acaf33f00a3bdc4e25895303fa72"
    ]
    testsC192 = [
      "0956259c9cd5cfd0181cca53380cde06", "8e4e18424e591a3d5b6f0876f16f8594",
      "93f3270cfc877ef17e106ce938979cb0", "7f6c25ff41858561bb62f36492e93c29",
      "8e06556dcbb00b809a025047cff2a940", "3608c344868e94555d23a120f8a5502d",
      "77da2021935b840b7f5dcc39132da9e5", "3b7c24f825e3bf9873c9f14d39a0e6f4",
      "64ebf95686b353508c90ecd8b6134316", "ff558c5d27210b7929b73fc708eb4cf1",
      "a2c3b2a818075490a7b4c14380f02702", "cfe4d74002696ccf7d87b14a2f9cafc9",
      "d2eafd86f63b109b91f5dbb3a3fb7e13", "9b9fdd1c5975655f539998b306a324af",
      "dd619e1cf204446112e0af2b9afa8f8c", "d4f0aae13c8fe9339fbf9e69ed0ad74d",
      "19c80ec4a6deb7e5ed1033dda933498f", "3cf5e1d21a17956d1dffad6a7c41c659",
      "69fd12e8505f8ded2fdcb197a121b362", "8aa584e2cc4d17417a97cb9a28ba29c8",
      "abc786fb1edb504580c4d882ef29a0c7", "2e19fb60a3e1de0166f483c97824a978",
      "7656709538dd5fec41e0ce6a0f8e207d", "a67cf333b314d411d3c0ae6e1cfcd8f5"
    ]
    testsK256 = [
      "c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558",
      "28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64",
      "c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c",
      "984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627",
      "b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f",
      "1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9",
      "dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf",
      "f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9",
      "797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e",
      "6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707",
      "ccd1bc3c659cd3c59bc437484e3c5c724441da8d6e90ce556cd57d0752663bbc",
      "13428b5e4c005e0636dd338405d173ab135dec2a25c22c5df0722d69dcc43887",
      "07eb03a08d291d1b07408bf3512ab40c91097ac77461aad4bb859647f74f00ee",
      "90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1",
      "b7a5794d52737475d53d5a377200849be0260a67a2b22ced8bbef12882270d07",
      "fca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e"
    ]
    testsC256 = [
      "46f2fb342d6f0ab477476fc501242c5f", "4bf3b0a69aeb6657794f2901b1440ad4",
      "352065272169abf9856843927d0674fd", "4307456a9e67813b452e15fa8fffe398",
      "4663446607354989477a5c6f0f007ef4", "531c2c38344578b84d50b3c917bbb6e1",
      "fc6aec906323480005c58e7e1ab004ad", "a3944b95ca0b52043584ef02151926a8",
      "a74289fe73a4c123ca189ea1e1b49ad5", "b91d4ea4488644b56cf0812fa7fcf5fc",
      "304f81ab61a80c2e743b94d5002a126b", "649a71545378c783e368c9ade7114f6c",
      "47cb030da2ab051dfc6c4bf6910d12bb", "798c7c005dee432b2c8ea5dfa381ecc3",
      "637c31dc2591a07636f646b72daabbe7", "179a49c712154bbffbe6e7a84a18e220"
    ]
    KCdata = "00000000000000000000000000000000"
    EPkey = "0000000000000000000000000000000000000000000000000000000000000000"


  test "RIJNDAEL/AES-128/192/256 block sizes":
    var a128: aes128
    var a192: aes192
    var a256: aes256
    var r128: rijndael128
    var r192: rijndael192
    var r256: rijndael256
    check:
      a128.sizeBlock == 16
      a192.sizeBlock == 16
      a256.sizeBlock == 16
      r128.sizeBlock == 16
      r192.sizeBlock == 16
      r256.sizeBlock == 16
      aes128.sizeBlock == 16
      aes192.sizeBlock == 16
      aes256.sizeBlock == 16
      rijndael128.sizeBlock == 16
      rijndael192.sizeBlock == 16
      rijndael256.sizeBlock == 16
  test "RIJNDAEL/AES-128/192/256 key sizes":
    var a128: aes128
    var a192: aes192
    var a256: aes256
    var r128: rijndael128
    var r192: rijndael192
    var r256: rijndael256
    check:
      a128.sizeKey == 16
      a192.sizeKey == 24
      a256.sizeKey == 32
      r128.sizeKey == 16
      r192.sizeKey == 24
      r256.sizeKey == 32
      aes128.sizeKey == 16
      aes192.sizeKey == 24
      aes256.sizeKey == 32
      rijndael128.sizeKey == 16
      rijndael192.sizeKey == 24
      rijndael256.sizeKey == 32
  test "AES-128 GFSbox test vectors":
    var i = 0
    while i < len(testsP128):
      var key = fromHex(EPkey)
      var data = fromHex(testsP128[i])
      var ctx: aes128
      ctx.init(addr key[0])
      ctx.encrypt(addr data[0], addr data[0])
      check(fromHex(testsE128[i]) == data)
      ctx.decrypt(addr data[0], addr data[0])
      check(data == fromHex(testsP128[i]))
      ctx.clear()
      check(ctx.isFullZero() == true)
      inc(i)

  test "AES-192 GFSbox test vectors":
    var i = 0
    while i < len(testsP192):
      var key = fromHex(EPkey)
      var data = fromHex(testsP192[i])
      var ctx: aes192
      ctx.init(addr key[0])
      ctx.encrypt(addr data[0], addr data[0])
      check(fromHex(testsE192[i]) == data)
      ctx.decrypt(addr data[0], addr data[0])
      check(data == fromHex(testsP192[i]))
      ctx.clear()
      check(ctx.isFullZero() == true)
      inc(i)

  test "AES-256 GFSbox test vectors":
    var i = 0
    while i < len(testsP256):
      var key = fromHex(EPkey)
      var data = fromHex(testsP256[i])
      var ctx: aes256
      ctx.init(addr key[0])
      ctx.encrypt(addr data[0], addr data[0])
      check(fromHex(testsE256[i]) == data)
      ctx.decrypt(addr data[0], addr data[0])
      check(data == fromHex(testsP256[i]))
      ctx.clear()
      check(ctx.isFullZero() == true)
      inc(i)

  test "AES-128 KeySbox test vectors":
    var i = 0
    while i < len(testsK128):
      var key = fromHex(testsK128[i])
      var data = fromHex(KCdata)
      var ctx: aes128
      ctx.init(addr key[0])
      ctx.encrypt(addr data[0], addr data[0])
      check(fromHex(testsC128[i]) == data)
      ctx.decrypt(addr data[0], addr data[0])
      check(toHex(data) == KCdata)
      ctx.clear()
      check(ctx.isFullZero() == true)
      inc(i)

  test "AES-192 KeySbox test vectors":
    var i = 0
    while i < len(testsK192):
      var key = fromHex(testsK192[i])
      var data = fromHex(KCdata)
      var ctx: aes192
      ctx.init(addr key[0])
      ctx.encrypt(addr data[0], addr data[0])
      check(fromHex(testsC192[i]) == data)
      ctx.decrypt(addr data[0], addr data[0])
      check(toHex(data) == KCdata)
      ctx.clear()
      check(ctx.isFullZero() == true)
      inc(i)

  test "AES-256 KeySbox test vectors":
    var i = 0
    while i < len(testsK256):
      var key = fromHex(testsK256[i])
      var data = fromHex(KCdata)
      var ctx: aes256
      ctx.init(addr key[0])
      ctx.encrypt(addr data[0], addr data[0])
      check(fromHex(testsC256[i]) == data)
      ctx.decrypt(addr data[0], addr data[0])
      check(toHex(data) == KCdata)
      ctx.clear()
      check(ctx.isFullZero() == true)
      inc(i)
