## bcmode

This module implements various Block Cipher Modes.

The five modes currently supported:

*   ECB (Electronic Code Book)
*   CBC (Cipher Block Chaining)
*   CFB (Cipher FeedBack)
*   OFB (Output FeedBack)
*   CTR (Counter)
*   GCM (Galois/Counter Mode)

You can use any of this modes with all the block ciphers of nimcrypto library

GHASH implementation is Nim version of `ghash_ctmul64.c` which is part of decent BearSSL project <[https://bearssl.org>](https://bearssl.org>). Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
