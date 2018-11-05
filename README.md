# nimcrypto [![Build Status](https://travis-ci.org/cheatfate/nimcrypto.svg?branch=master)](https://travis-ci.org/cheatfate/nimcrypto) [![Build Status](https://ci.appveyor.com/api/projects/status/github/cheatfate/nimcrypto?branch=master&svg=true)](https://ci.appveyor.com/project/cheatfate/nimcrypto)

# Nim cryptographic library

Nimcrypto is Nim's cryptographic library. It implements several popular cryptographic algorithms and their tests with some [examples](https://github.com/cheatfate/nimcrypto/tree/master/examples).
  
Most notably, this library has been used in the [Nimbus Ethereum client](https://our.status.im/nimbus-for-newbies/). To see the implementation, check out its [Github repository](https://github.com/status-im/nimbus).


## The most basic usage

```bash
nimble install nimcrypto # installation
```

```nim
# example.nim
import nimcrypto

echo keccak_256.digest("Alice makes a hash") 
# outputs EF0CC652868DF797522FB1D5A39E58E069154D9E47E5D7DB288B7200DB6EDFEE
```

See full documentation [here](https://cheatfate.github.io/nimcrypto).