#
#
#                    NimCrypto
#        (c) Copyright 2020 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements Rijndael(AES) crypto algorithm by Vincent Rijmen,
## Antoon Bosselaers and Paulo Barreto.
##
## This code is Nim version of `aes_ct.c` and `aes_ct64.c` which is part
## of decent BearSSL project <https://bearssl.org>.
## Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
##
## Tests made according to official test vectors (Appendix B and Appendix C)
## [http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf].
import utils

{.deadCodeElim:on.}

when sizeof(int) == 4:
  type
    RijndaelContext[bits: static[uint]] = object
      skey: array[120, uint32]
      nr: int
elif sizeof(int) == 8:
  type
    RijndaelContext[bits: static[uint]] = object
      skey: array[120, uint64]
      nr: int

const Rcon = [0x01'u8, 0x02'u8, 0x04'u8, 0x08'u8, 0x10'u8,
              0x20'u8, 0x40'u8, 0x80'u8, 0x1B'u8, 0x36'u8]

type
  rijndael128* = RijndaelContext[128]
  rijndael192* = RijndaelContext[192]
  rijndael256* = RijndaelContext[256]
  aes128* = rijndael128
  aes192* = rijndael192
  aes256* = rijndael256
  rijndael* = rijndael128 | rijndael192 | rijndael256 | aes128 | aes192 | aes256

when sizeof(int) == 4:
  proc bitsliceSbox(q: var array[8, uint32]) =
    var
      x0, x1, x2, x3, x4, x5, x6, x7: uint32
      y1, y2, y3, y4, y5, y6, y7, y8, y9: uint32
      y10, y11, y12, y13, y14, y15, y16, y17, y18, y19: uint32
      y20, y21: uint32
      z0, z1, z2, z3, z4, z5, z6, z7, z8, z9: uint32
      z10, z11, z12, z13, z14, z15, z16, z17: uint32
      t0, t1, t2, t3, t4, t5, t6, t7, t8, t9: uint32
      t10, t11, t12, t13, t14, t15, t16, t17, t18, t19: uint32
      t20, t21, t22, t23, t24, t25, t26, t27, t28, t29: uint32
      t30, t31, t32, t33, t34, t35, t36, t37, t38, t39: uint32
      t40, t41, t42, t43, t44, t45, t46, t47, t48, t49: uint32
      t50, t51, t52, t53, t54, t55, t56, t57, t58, t59: uint32
      t60, t61, t62, t63, t64, t65, t66, t67: uint32
      s0, s1, s2, s3, s4, s5, s6, s7: uint32

    x0 = q[7]
    x1 = q[6]
    x2 = q[5]
    x3 = q[4]
    x4 = q[3]
    x5 = q[2]
    x6 = q[1]
    x7 = q[0]

    # Top linear transformation.
    y14 = x3 xor x5
    y13 = x0 xor x6
    y9 = x0 xor x3
    y8 = x0 xor x5
    t0 = x1 xor x2
    y1 = t0 xor x7
    y4 = y1 xor x3
    y12 = y13 xor y14
    y2 = y1 xor x0
    y5 = y1 xor x6
    y3 = y5 xor y8
    t1 = x4 xor y12
    y15 = t1 xor x5
    y20 = t1 xor x1
    y6 = y15 xor x7
    y10 = y15 xor t0
    y11 = y20 xor y9
    y7 = x7 xor y11
    y17 = y10 xor y11
    y19 = y10 xor y8
    y16 = t0 xor y11
    y21 = y13 xor y16
    y18 = x0 xor y16

    # Non-linear section.
    t2 = y12 and y15
    t3 = y3 and y6
    t4 = t3 xor t2
    t5 = y4 and x7
    t6 = t5 xor t2
    t7 = y13 and y16
    t8 = y5 and y1
    t9 = t8 xor t7
    t10 = y2 and y7
    t11 = t10 xor t7
    t12 = y9 and y11
    t13 = y14 and y17
    t14 = t13 xor t12
    t15 = y8 and y10
    t16 = t15 xor t12
    t17 = t4 xor t14
    t18 = t6 xor t16
    t19 = t9 xor t14
    t20 = t11 xor t16
    t21 = t17 xor y20
    t22 = t18 xor y19
    t23 = t19 xor y21
    t24 = t20 xor y18

    t25 = t21 xor t22
    t26 = t21 and t23
    t27 = t24 xor t26
    t28 = t25 and t27
    t29 = t28 xor t22
    t30 = t23 xor t24
    t31 = t22 xor t26
    t32 = t31 and t30
    t33 = t32 xor t24
    t34 = t23 xor t33
    t35 = t27 xor t33
    t36 = t24 and t35
    t37 = t36 xor t34
    t38 = t27 xor t36
    t39 = t29 and t38
    t40 = t25 xor t39

    t41 = t40 xor t37
    t42 = t29 xor t33
    t43 = t29 xor t40
    t44 = t33 xor t37
    t45 = t42 xor t41
    z0 = t44 and y15
    z1 = t37 and y6
    z2 = t33 and x7
    z3 = t43 and y16
    z4 = t40 and y1
    z5 = t29 and y7
    z6 = t42 and y11
    z7 = t45 and y17
    z8 = t41 and y10
    z9 = t44 and y12
    z10 = t37 and y3
    z11 = t33 and y4
    z12 = t43 and y13
    z13 = t40 and y5
    z14 = t29 and y2
    z15 = t42 and y9
    z16 = t45 and y14
    z17 = t41 and y8

    # Bottom linear transformation.
    t46 = z15 xor z16
    t47 = z10 xor z11
    t48 = z5 xor z13
    t49 = z9 xor z10
    t50 = z2 xor z12
    t51 = z2 xor z5
    t52 = z7 xor z8
    t53 = z0 xor z3
    t54 = z6 xor z7
    t55 = z16 xor z17
    t56 = z12 xor t48
    t57 = t50 xor t53
    t58 = z4 xor t46
    t59 = z3 xor t54
    t60 = t46 xor t57
    t61 = z14 xor t57
    t62 = t52 xor t58
    t63 = t49 xor t58
    t64 = z4 xor t59
    t65 = t61 xor t62
    t66 = z1 xor t63
    s0 = t59 xor t63
    s6 = t56 xor not(t62)
    s7 = t48 xor not(t60)
    t67 = t64 xor t65
    s3 = t53 xor t66
    s4 = t51 xor t66
    s5 = t47 xor t65
    s1 = t64 xor not(s3)
    s2 = t55 xor not(t67)

    q[7] = s0
    q[6] = s1
    q[5] = s2
    q[4] = s3
    q[3] = s4
    q[2] = s5
    q[1] = s6
    q[0] = s7

  proc bitsliceInvSbox(q: var array[8, uint32]) {.inline.} =
    var
      q0, q1, q2, q3, q4, q5, q6, q7: uint32
    q0 = not(q[0])
    q1 = not(q[1])
    q2 = q[2]
    q3 = q[3]
    q4 = q[4]
    q5 = not(q[5])
    q6 = not(q[6])
    q7 = q[7]
    q[7] = q1 xor q4 xor q6
    q[6] = q0 xor q3 xor q5
    q[5] = q7 xor q2 xor q4
    q[4] = q6 xor q1 xor q3
    q[3] = q5 xor q0 xor q2
    q[2] = q4 xor q7 xor q1
    q[1] = q3 xor q6 xor q0
    q[0] = q2 xor q5 xor q7
    bitsliceSbox(q)
    q0 = not(q[0])
    q1 = not(q[1])
    q2 = q[2]
    q3 = q[3]
    q4 = q[4]
    q5 = not(q[5])
    q6 = not(q[6])
    q7 = q[7]
    q[7] = q1 xor q4 xor q6
    q[6] = q0 xor q3 xor q5
    q[5] = q7 xor q2 xor q4
    q[4] = q6 xor q1 xor q3
    q[3] = q5 xor q0 xor q2
    q[2] = q4 xor q7 xor q1
    q[1] = q3 xor q6 xor q0
    q[0] = q2 xor q5 xor q7

  proc ortho(q: var openArray[uint32]) {.inline.} =
    template swapN(cl, ch, s, x, y) =
      var a, b: uint32
      a = x
      b = y
      x = (a and uint32(cl)) or ((b and uint32(cl)) shl s)
      y = ((a and uint32(ch)) shr s) or (b and uint32(ch))

    template swap2(x, y) =
      swapN(0x5555_5555, 0xAAAA_AAAA, 1, x, y)
    template swap4(x, y) =
      swapN(0x3333_3333, 0xCCCC_CCCC, 2, x, y)
    template swap8(x, y) =
      swapN(0x0F0F_0F0F, 0xF0F0_F0F0, 4, x, y)

    swap2(q[0], q[1])
    swap2(q[2], q[3])
    swap2(q[4], q[5])
    swap2(q[6], q[7])

    swap4(q[0], q[2])
    swap4(q[1], q[3])
    swap4(q[4], q[6])
    swap4(q[5], q[7])

    swap8(q[0], q[4])
    swap8(q[1], q[5])
    swap8(q[2], q[6])
    swap8(q[3], q[7])

  proc subWord(x: uint32): uint32 =
    var q {.noinit.}: array[8, uint32]
    q[0] = x
    q[1] = x
    q[2] = x
    q[3] = x
    q[4] = x
    q[5] = x
    q[6] = x
    q[7] = x
    ortho(q)
    bitsliceSbox(q)
    ortho(q)
    q[0]

  proc keySchedule(ctx: var RijndaelContext, key: openArray[byte]) =
    var tmp = 0'u32
    var j, k: int

    when ctx.bits == 128:
      ctx.nr = 10
      ctx.skey[0] = leLoad32(key, 0)
      ctx.skey[1] = ctx.skey[0]
      ctx.skey[2] = leLoad32(key, 4)
      ctx.skey[3] = ctx.skey[2]
      ctx.skey[4] = leLoad32(key, 8)
      ctx.skey[5] = ctx.skey[4]
      ctx.skey[6] = leLoad32(key, 12)
      ctx.skey[7] = ctx.skey[6]
      tmp = ctx.skey[6]
    elif ctx.bits == 192:
      ctx.nr = 12
      ctx.skey[0] = leLoad32(key, 0)
      ctx.skey[1] = ctx.skey[0]
      ctx.skey[2] = leLoad32(key, 4)
      ctx.skey[3] = ctx.skey[2]
      ctx.skey[4] = leLoad32(key, 8)
      ctx.skey[5] = ctx.skey[4]
      ctx.skey[6] = leLoad32(key, 12)
      ctx.skey[7] = ctx.skey[6]
      ctx.skey[8] = leLoad32(key, 16)
      ctx.skey[9] = ctx.skey[8]
      ctx.skey[10] = leLoad32(key, 20)
      ctx.skey[11] = ctx.skey[10]
      tmp = ctx.skey[10]
    elif ctx.bits == 256:
      ctx.nr = 14
      ctx.skey[0] = leLoad32(key, 0)
      ctx.skey[1] = ctx.skey[0]
      ctx.skey[2] = leLoad32(key, 4)
      ctx.skey[3] = ctx.skey[2]
      ctx.skey[4] = leLoad32(key, 8)
      ctx.skey[5] = ctx.skey[4]
      ctx.skey[6] = leLoad32(key, 12)
      ctx.skey[7] = ctx.skey[6]
      ctx.skey[8] = leLoad32(key, 16)
      ctx.skey[9] = ctx.skey[8]
      ctx.skey[10] = leLoad32(key, 20)
      ctx.skey[11] = ctx.skey[10]
      ctx.skey[12] = leLoad32(key, 24)
      ctx.skey[13] = ctx.skey[12]
      ctx.skey[14] = leLoad32(key, 28)
      ctx.skey[15] = ctx.skey[14]
      tmp = ctx.skey[14]

    let nk = (ctx.bits div 8) shr 2
    let nkf = (ctx.nr + 1) shl 2

    j = 0
    k = 0
    for i in nk ..< nkf:
      if j == 0:
        tmp = (tmp shl 24) or (tmp shr 8)
        tmp = subWord(tmp) xor Rcon[k]
      elif (nk > 6) and (j == 4):
        tmp = subWord(tmp)
      tmp = tmp xor ctx.skey[(i - nk) shl 1]
      ctx.skey[(i shl 1) + 0] = tmp
      ctx.skey[(i shl 1) + 1] = tmp
      inc(j)
      if j == nk:
        j = 0
        inc(k)

    k = 0
    while k < nkf:
      let i = k shl 1
      ortho(ctx.skey.toOpenArray(i, i + 7))
      inc(k, 4)

  template addRoundKey(q, sk, offset: untyped) =
    q[0] = q[0] xor sk[offset + 0]
    q[1] = q[1] xor sk[offset + 1]
    q[2] = q[2] xor sk[offset + 2]
    q[3] = q[3] xor sk[offset + 3]
    q[4] = q[4] xor sk[offset + 4]
    q[5] = q[5] xor sk[offset + 5]
    q[6] = q[6] xor sk[offset + 6]
    q[7] = q[7] xor sk[offset + 7]

  template shiftRows(q: untyped) =
    for i in 0 ..< 8:
      let x = q[i]
      q[i] = (x and 0x0000_00FF'u32) or
            (((x and 0x0000_FC00'u32) shr 2) or ((x and 0x0000_0300) shl 6)) or
            (((x and 0x00F0_0000'u32) shr 4) or ((x and 0x000F_0000) shl 4)) or
             (((x and 0xC000_0000'u32) shr 6) or ((x and 0x3F00_0000) shl 2))

  template invShiftRows(q: untyped) =
    for i in 0 ..< 8:
      let x = q[i]
      q[i] = (x and 0x0000_00FF'u32) or
        (((x and 0x0000_3F00'u32) shl 2) or ((x and 0x0000_C000'u32) shr 6)) or
        (((x and 0x000F_0000'u32) shl 4) or ((x and 0x00F0_0000'u32) shr 4)) or
        (((x and 0x0300_0000'u32) shl 6) or ((x and 0xFC00_0000'u32) shr 2))

  template rotr16(x: uint32): uint32 =
    (x shl 16) or (x shr 16)

  template mixColumns(q: untyped) =
    let q0 = q[0]
    let q1 = q[1]
    let q2 = q[2]
    let q3 = q[3]
    let q4 = q[4]
    let q5 = q[5]
    let q6 = q[6]
    let q7 = q[7]
    let r0 = (q0 shr 8) or (q0 shl 24)
    let r1 = (q1 shr 8) or (q1 shl 24)
    let r2 = (q2 shr 8) or (q2 shl 24)
    let r3 = (q3 shr 8) or (q3 shl 24)
    let r4 = (q4 shr 8) or (q4 shl 24)
    let r5 = (q5 shr 8) or (q5 shl 24)
    let r6 = (q6 shr 8) or (q6 shl 24)
    let r7 = (q7 shr 8) or (q7 shl 24)
    let v0 = q0 xor r0
    let v1 = q1 xor r1
    let v2 = q2 xor r2
    let v3 = q3 xor r3
    let v4 = q4 xor r4
    let v5 = q5 xor r5
    let v6 = q6 xor r6
    let v7 = q7 xor r7
    q[0] = q7 xor r7 xor r0 xor rotr16(v0)
    q[1] = q0 xor r0 xor q7 xor r7 xor r1 xor rotr16(v1)
    q[2] = q1 xor r1 xor r2 xor rotr16(v2)
    q[3] = q2 xor r2 xor q7 xor r7 xor r3 xor rotr16(v3)
    q[4] = q3 xor r3 xor q7 xor r7 xor r4 xor rotr16(v4)
    q[5] = q4 xor r4 xor r5 xor rotr16(v5)
    q[6] = q5 xor r5 xor r6 xor rotr16(v6)
    q[7] = q6 xor r6 xor r7 xor rotr16(v7)

  template invMixColumns(q: untyped) =
    let q0 = q[0]
    let q1 = q[1]
    let q2 = q[2]
    let q3 = q[3]
    let q4 = q[4]
    let q5 = q[5]
    let q6 = q[6]
    let q7 = q[7]
    let r0 = (q0 shr 8) or (q0 shl 24)
    let r1 = (q1 shr 8) or (q1 shl 24)
    let r2 = (q2 shr 8) or (q2 shl 24)
    let r3 = (q3 shr 8) or (q3 shl 24)
    let r4 = (q4 shr 8) or (q4 shl 24)
    let r5 = (q5 shr 8) or (q5 shl 24)
    let r6 = (q6 shr 8) or (q6 shl 24)
    let r7 = (q7 shr 8) or (q7 shl 24)
    let v0 = q0 xor q5 xor q6 xor r0 xor r5
    let v1 = q1 xor q5 xor q7 xor r1 xor r5 xor r6
    let v2 = q0 xor q2 xor q6 xor r2 xor r6 xor r7
    let v3 = q0 xor q1 xor q3 xor q5 xor q6 xor q7 xor r0 xor r3 xor r5 xor r7
    let v4 = q1 xor q2 xor q4 xor q5 xor q7 xor r1 xor r4 xor r5 xor r6
    let v5 = q2 xor q3 xor q5 xor q6 xor r2 xor r5 xor r6 xor r7
    let v6 = q3 xor q4 xor q6 xor q7 xor r3 xor r6 xor r7
    let v7 = q4 xor q5 xor q7 xor r4 xor r7
    q[0] = q5 xor q6 xor q7 xor r0 xor r5 xor r7 xor rotr16(v0)
    q[1] = q0 xor q5 xor r0 xor r1 xor r5 xor r6 xor r7 xor rotr16(v1)
    q[2] = q0 xor q1 xor q6 xor r1 xor r2 xor r6 xor r7 xor rotr16(v2)
    q[3] = q0 xor q1 xor q2 xor q5 xor q6 xor r0 xor r2 xor r3 xor r5 xor
           rotr16(v3)
    q[4] = q1 xor q2 xor q3 xor q5 xor r1 xor r3 xor r4 xor r5 xor r6 xor r7 xor
           rotr16(v4)
    q[5] = q2 xor q3 xor q4 xor q6 xor r2 xor r4 xor r5 xor r6 xor r7 xor
           rotr16(v5)
    q[6] = q3 xor q4 xor q5 xor q7 xor r3 xor r5 xor r6 xor r7 xor rotr16(v6)
    q[7] = q4 xor q5 xor q6 xor r4 xor r6 xor r7 xor rotr16(v7)

  proc encrypt*(ctx: RijndaelContext, input: openArray[byte],
                output: var openArray[byte]) =
    var q {.noinit.}: array[8, uint32]
    q[0] = leLoad32(input, 0)
    q[2] = leLoad32(input, 4)
    q[4] = leLoad32(input, 8)
    q[6] = leLoad32(input, 12)

    ortho(q)
    addRoundKey(q, ctx.skey, 0)
    for u in 1 ..< ctx.nr:
      bitsliceSbox(q)
      shiftRows(q)
      mixColumns(q)
      let offset = u shl 3
      addRoundKey(q, ctx.skey, offset)

    bitsliceSbox(q)
    shiftRows(q)
    let offset = ctx.nr shl 3
    addRoundKey(q, ctx.skey, offset)

    ortho(q)
    leStore32(output, 0, q[0])
    leStore32(output, 4, q[2])
    leStore32(output, 8, q[4])
    leStore32(output, 12, q[6])

  proc decrypt*(ctx: RijndaelContext, input: openArray[byte],
                output: var openArray[byte]) =
    var q {.noinit.}: array[8, uint32]
    q[0] = leLoad32(input, 0)
    q[2] = leLoad32(input, 4)
    q[4] = leLoad32(input, 8)
    q[6] = leLoad32(input, 12)

    ortho(q)
    let offset = ctx.nr shl 3
    addRoundKey(q, ctx.skey, offset)
    for u in countdown(ctx.nr - 1, 1):
      invShiftRows(q)
      bitsliceInvSbox(q)
      let offset = u shl 3
      addRoundKey(q, ctx.skey, offset)
      invMixColumns(q)

    invShiftRows(q)
    bitsliceInvSbox(q)
    addRoundKey(q, ctx.skey, 0)

    ortho(q)
    leStore32(output, 0, q[0])
    leStore32(output, 4, q[2])
    leStore32(output, 8, q[4])
    leStore32(output, 12, q[6])

elif sizeof(int) == 8:
  proc bitsliceSbox(q: var array[8, uint64]) {.inline.} =
    var
      x0, x1, x2, x3, x4, x5, x6, x7: uint64
      y1, y2, y3, y4, y5, y6, y7, y8, y9: uint64
      y10, y11, y12, y13, y14, y15, y16, y17, y18, y19: uint64
      y20, y21: uint64
      z0, z1, z2, z3, z4, z5, z6, z7, z8, z9: uint64
      z10, z11, z12, z13, z14, z15, z16, z17: uint64
      t0, t1, t2, t3, t4, t5, t6, t7, t8, t9: uint64
      t10, t11, t12, t13, t14, t15, t16, t17, t18, t19: uint64
      t20, t21, t22, t23, t24, t25, t26, t27, t28, t29: uint64
      t30, t31, t32, t33, t34, t35, t36, t37, t38, t39: uint64
      t40, t41, t42, t43, t44, t45, t46, t47, t48, t49: uint64
      t50, t51, t52, t53, t54, t55, t56, t57, t58, t59: uint64
      t60, t61, t62, t63, t64, t65, t66, t67: uint64
      s0, s1, s2, s3, s4, s5, s6, s7: uint64

    x0 = q[7]
    x1 = q[6]
    x2 = q[5]
    x3 = q[4]
    x4 = q[3]
    x5 = q[2]
    x6 = q[1]
    x7 = q[0]

    # Top linear transformation.
    y14 = x3 xor x5
    y13 = x0 xor x6
    y9 = x0 xor x3
    y8 = x0 xor x5
    t0 = x1 xor x2
    y1 = t0 xor x7
    y4 = y1 xor x3
    y12 = y13 xor y14
    y2 = y1 xor x0
    y5 = y1 xor x6
    y3 = y5 xor y8
    t1 = x4 xor y12
    y15 = t1 xor x5
    y20 = t1 xor x1
    y6 = y15 xor x7
    y10 = y15 xor t0
    y11 = y20 xor y9
    y7 = x7 xor y11
    y17 = y10 xor y11
    y19 = y10 xor y8
    y16 = t0 xor y11
    y21 = y13 xor y16
    y18 = x0 xor y16

    # Non-linear section.
    t2 = y12 and y15
    t3 = y3 and y6
    t4 = t3 xor t2
    t5 = y4 and x7
    t6 = t5 xor t2
    t7 = y13 and y16
    t8 = y5 and y1
    t9 = t8 xor t7
    t10 = y2 and y7
    t11 = t10 xor t7
    t12 = y9 and y11
    t13 = y14 and y17
    t14 = t13 xor t12
    t15 = y8 and y10
    t16 = t15 xor t12
    t17 = t4 xor t14
    t18 = t6 xor t16
    t19 = t9 xor t14
    t20 = t11 xor t16
    t21 = t17 xor y20
    t22 = t18 xor y19
    t23 = t19 xor y21
    t24 = t20 xor y18

    t25 = t21 xor t22
    t26 = t21 and t23
    t27 = t24 xor t26
    t28 = t25 and t27
    t29 = t28 xor t22
    t30 = t23 xor t24
    t31 = t22 xor t26
    t32 = t31 and t30
    t33 = t32 xor t24
    t34 = t23 xor t33
    t35 = t27 xor t33
    t36 = t24 and t35
    t37 = t36 xor t34
    t38 = t27 xor t36
    t39 = t29 and t38
    t40 = t25 xor t39

    t41 = t40 xor t37
    t42 = t29 xor t33
    t43 = t29 xor t40
    t44 = t33 xor t37
    t45 = t42 xor t41
    z0 = t44 and y15
    z1 = t37 and y6
    z2 = t33 and x7
    z3 = t43 and y16
    z4 = t40 and y1
    z5 = t29 and y7
    z6 = t42 and y11
    z7 = t45 and y17
    z8 = t41 and y10
    z9 = t44 and y12
    z10 = t37 and y3
    z11 = t33 and y4
    z12 = t43 and y13
    z13 = t40 and y5
    z14 = t29 and y2
    z15 = t42 and y9
    z16 = t45 and y14
    z17 = t41 and y8

    # Bottom linear transformation.
    t46 = z15 xor z16
    t47 = z10 xor z11
    t48 = z5 xor z13
    t49 = z9 xor z10
    t50 = z2 xor z12
    t51 = z2 xor z5
    t52 = z7 xor z8
    t53 = z0 xor z3
    t54 = z6 xor z7
    t55 = z16 xor z17
    t56 = z12 xor t48
    t57 = t50 xor t53
    t58 = z4 xor t46
    t59 = z3 xor t54
    t60 = t46 xor t57
    t61 = z14 xor t57
    t62 = t52 xor t58
    t63 = t49 xor t58
    t64 = z4 xor t59
    t65 = t61 xor t62
    t66 = z1 xor t63
    s0 = t59 xor t63
    s6 = t56 xor not(t62)
    s7 = t48 xor not(t60)
    t67 = t64 xor t65
    s3 = t53 xor t66
    s4 = t51 xor t66
    s5 = t47 xor t65
    s1 = t64 xor not(s3)
    s2 = t55 xor not(t67)

    q[7] = s0
    q[6] = s1
    q[5] = s2
    q[4] = s3
    q[3] = s4
    q[2] = s5
    q[1] = s6
    q[0] = s7

  proc bitsliceInvSbox(q: var array[8, uint64]) {.inline.} =
    var q0 = not(q[0])
    var q1 = not(q[1])
    var q2 = q[2]
    var q3 = q[3]
    var q4 = q[4]
    var q5 = not(q[5])
    var q6 = not(q[6])
    var q7 = q[7]

    q[7] = q1 xor q4 xor q6
    q[6] = q0 xor q3 xor q5
    q[5] = q7 xor q2 xor q4
    q[4] = q6 xor q1 xor q3
    q[3] = q5 xor q0 xor q2
    q[2] = q4 xor q7 xor q1
    q[1] = q3 xor q6 xor q0
    q[0] = q2 xor q5 xor q7

    bitsliceSbox(q)

    q0 = not(q[0])
    q1 = not(q[1])
    q2 = q[2]
    q3 = q[3]
    q4 = q[4]
    q5 = not(q[5])
    q6 = not(q[6])
    q7 = q[7]
    q[7] = q1 xor q4 xor q6
    q[6] = q0 xor q3 xor q5
    q[5] = q7 xor q2 xor q4
    q[4] = q6 xor q1 xor q3
    q[3] = q5 xor q0 xor q2
    q[2] = q4 xor q7 xor q1
    q[1] = q3 xor q6 xor q0
    q[0] = q2 xor q5 xor q7

  proc ortho(q: var array[8, uint64]) =
    template swapN(cl, ch, s, x, y) =
      var a, b: uint64
      a = x
      b = y
      x = (a and uint64(cl)) or ((b and uint64(cl)) shl s)
      y = ((a and uint64(ch)) shr s) or (b and uint64(ch))

    template swap2(x, y) =
      swapN(0x5555_5555_5555_5555'u64, 0xAAAA_AAAA_AAAA_AAAA'u64, 1, x, y)
    template swap4(x, y) =
      swapN(0x3333_3333_3333_3333'u64, 0xCCCC_CCCC_CCCC_CCCC'u64, 2, x, y)
    template swap8(x, y) =
      swapN(0x0F0F_0F0F_0F0F_0F0F'u64, 0xF0F0_F0F0_F0F0_F0F0'u64, 4, x, y)

    swap2(q[0], q[1])
    swap2(q[2], q[3])
    swap2(q[4], q[5])
    swap2(q[6], q[7])

    swap4(q[0], q[2])
    swap4(q[1], q[3])
    swap4(q[4], q[6])
    swap4(q[5], q[7])

    swap8(q[0], q[4])
    swap8(q[1], q[5])
    swap8(q[2], q[6])
    swap8(q[3], q[7])

  proc interleaveIn(q0: var uint64, q1: var uint64,
                    w: openArray[uint32]) {.inline.} =
    var x0, x1, x2, x3: uint64

    x0 = w[0]
    x1 = w[1]
    x2 = w[2]
    x3 = w[3]
    x0 = x0 or (x0 shl 16)
    x1 = x1 or (x1 shl 16)
    x2 = x2 or (x2 shl 16)
    x3 = x3 or (x3 shl 16)
    x0 = x0 and 0x0000_FFFF_0000_FFFF'u64
    x1 = x1 and 0x0000_FFFF_0000_FFFF'u64
    x2 = x2 and 0x0000_FFFF_0000_FFFF'u64
    x3 = x3 and 0x0000_FFFF_0000_FFFF'u64
    x0 = x0 or (x0 shl 8)
    x1 = x1 or (x1 shl 8)
    x2 = x2 or (x2 shl 8)
    x3 = x3 or (x3 shl 8)
    x0 = x0 and 0x00FF_00FF_00FF_00FF'u64
    x1 = x1 and 0x00FF_00FF_00FF_00FF'u64
    x2 = x2 and 0x00FF_00FF_00FF_00FF'u64
    x3 = x3 and 0x00FF_00FF_00FF_00FF'u64
    q0 = x0 or (x2 shl 8)
    q1 = x1 or (x3 shl 8)

  proc interleaveOut(w: var openArray[uint32], q0: uint64,
                     q1: uint64) {.inline.} =
    var x0, x1, x2, x3: uint64

    x0 = q0 and 0x00FF_00FF_00FF_00FF'u64
    x1 = q1 and 0x00FF_00FF_00FF_00FF'u64
    x2 = (q0 shr 8) and 0x00FF_00FF_00FF_00FF'u64
    x3 = (q1 shr 8) and 0x00FF_00FF_00FF_00FF'u64
    x0 = x0 or (x0 shr 8)
    x1 = x1 or (x1 shr 8)
    x2 = x2 or (x2 shr 8)
    x3 = x3 or (x3 shr 8)
    x0 = x0 and 0x0000_FFFF_0000_FFFF'u64
    x1 = x1 and 0x0000_FFFF_0000_FFFF'u64
    x2 = x2 and 0x0000_FFFF_0000_FFFF'u64
    x3 = x3 and 0x0000_FFFF_0000_FFFF'u64
    w[0] = uint32(x0 and 0xFFFF_FFFF'u64) or
           uint32((x0 shr 16) and 0xFFFF_FFFF'u64)
    w[1] = uint32(x1 and 0xFFFF_FFFF'u64) or
           uint32((x1 shr 16) and 0xFFFF_FFFF'u64)
    w[2] = uint32(x2 and 0xFFFF_FFFF'u64) or
           uint32((x2 shr 16) and 0xFFFF_FFFF'u64)
    w[3] = uint32(x3 and 0xFFFF_FFFF'u64) or
           uint32((x3 shr 16) and 0xFFFF_FFFF'u64)

  proc subWord(x: uint32): uint32 =
    var q: array[8, uint64]
    q[0] = uint64(x)
    ortho(q)
    bitsliceSbox(q)
    ortho(q)
    uint32(q[0] and 0xFFFF_FFFF'u64)

  proc keySchedule(ctx: var RijndaelContext, key: openArray[byte]) =
    var skey: array[60, uint32]
    var tkey: array[30, uint64]
    var tmp = 0'u32
    var j, k: int

    when ctx.bits == 128:
      ctx.nr = 10
      skey[0] = leLoad32(key, 0)
      skey[1] = leLoad32(key, 4)
      skey[2] = leLoad32(key, 8)
      skey[3] = leLoad32(key, 12)
      tmp = skey[3]
    elif ctx.bits == 192:
      ctx.nr = 12
      skey[0] = leLoad32(key, 0)
      skey[1] = leLoad32(key, 4)
      skey[2] = leLoad32(key, 8)
      skey[3] = leLoad32(key, 12)
      skey[4] = leLoad32(key, 16)
      skey[5] = leLoad32(key, 20)
      tmp = skey[5]
    elif ctx.bits == 256:
      ctx.nr = 14
      skey[0] = leLoad32(key, 0)
      skey[1] = leLoad32(key, 4)
      skey[2] = leLoad32(key, 8)
      skey[3] = leLoad32(key, 12)
      skey[4] = leLoad32(key, 16)
      skey[5] = leLoad32(key, 20)
      skey[6] = leLoad32(key, 24)
      skey[7] = leLoad32(key, 28)
      tmp = skey[7]

    let nk = (ctx.bits div 8) shr 2
    let nkf = (ctx.nr + 1) shl 2

    j = 0
    k = 0
    for i in nk ..< nkf:
      if j == 0:
        tmp = (tmp shl 24) or (tmp shr 8)
        tmp = subWord(tmp) xor Rcon[k]
      elif (nk > 6) and (j == 4):
        tmp = subWord(tmp)
      tmp = tmp xor skey[i - nk]
      skey[i] = tmp
      inc(j)
      if j == nk:
        j = 0
        inc(k)

    j = 0
    k = 0
    while k < nkf:
      var q: array[8, uint64]
      interleaveIn(q[0], q[4], skey.toOpenArray(k, k + 3))
      q[1] = q[0]
      q[2] = q[0]
      q[3] = q[0]
      q[5] = q[4]
      q[6] = q[4]
      q[7] = q[4]
      ortho(q)
      tkey[j + 0] = (q[0] and 0x1111_1111_1111_1111'u64) or
                    (q[1] and 0x2222_2222_2222_2222'u64) or
                    (q[2] and 0x4444_4444_4444_4444'u64) or
                    (q[3] and 0x8888_8888_8888_8888'u64)
      tkey[j + 1] = (q[4] and 0x1111_1111_1111_1111'u64) or
                    (q[5] and 0x2222_2222_2222_2222'u64) or
                    (q[6] and 0x4444_4444_4444_4444'u64) or
                    (q[7] and 0x8888_8888_8888_8888'u64)
      inc(j, 2)
      inc(k, 4)

    j = 0
    for i in 0 ..< ((ctx.nr + 1) shl 1):
      let x = tkey[i]
      let x0 = (x and 0x1111_1111_1111_1111'u64)
      let x1 = (x and 0x2222_2222_2222_2222'u64) shr 1
      let x2 = (x and 0x4444_4444_4444_4444'u64) shr 2
      let x3 = (x and 0x8888_8888_8888_8888'u64) shr 3
      ctx.skey[j + 0] = (x0 shl 4) - x0
      ctx.skey[j + 1] = (x1 shl 4) - x1
      ctx.skey[j + 2] = (x2 shl 4) - x2
      ctx.skey[j + 3] = (x3 shl 4) - x3
      inc(j, 4)

  template addRoundKey(q, sk, offset: untyped) =
    q[0] = q[0] xor sk[0 + offset]
    q[1] = q[1] xor sk[1 + offset]
    q[2] = q[2] xor sk[2 + offset]
    q[3] = q[3] xor sk[3 + offset]
    q[4] = q[4] xor sk[4 + offset]
    q[5] = q[5] xor sk[5 + offset]
    q[6] = q[6] xor sk[6 + offset]
    q[7] = q[7] xor sk[7 + offset]

  template shiftRows(q: untyped) =
    for i in 0 ..< 8:
      let x = q[i]
      q[i] = (x and 0x000000000000FFFF'u64) or
             ((x and 0x0000_0000_FFF0_0000'u64) shr 4) or
             ((x and 0x0000_0000_000F_0000'u64) shl 12) or
             ((x and 0x0000_FF00_0000_0000'u64) shr 8) or
             ((x and 0x0000_00FF_0000_0000'u64) shl 8) or
             ((x and 0xF000_0000_0000_0000'u64) shr 12) or
             ((x and 0x0FFF_0000_0000_0000'u64) shl 4)

  template invShiftRows(q: untyped) =
    for i in 0 ..< 8:
      let x = q[i]
      q[i] = (x and 0x0000_0000_0000_FFFF'u64) or
             ((x and 0x0000_0000_0FFF_0000'u64) shl 4) or
             ((x and 0x0000_0000_F000_0000'u64) shr 12) or
             ((x and 0x0000_00FF_0000_0000'u64) shl 8) or
             ((x and 0x0000_FF00_0000_0000'u64) shr 8) or
             ((x and 0x000F_0000_0000_0000'u64) shl 12) or
             ((x and 0xFFF0_0000_0000_0000'u64) shr 4)

  template rotr32(x: uint64): uint64 =
    (x shl 32) or (x shr 32)

  template mixColumns(q: untyped) =
    let q0 = q[0]
    let q1 = q[1]
    let q2 = q[2]
    let q3 = q[3]
    let q4 = q[4]
    let q5 = q[5]
    let q6 = q[6]
    let q7 = q[7]
    let r0 = (q0 shr 16) or (q0 shl 48)
    let r1 = (q1 shr 16) or (q1 shl 48)
    let r2 = (q2 shr 16) or (q2 shl 48)
    let r3 = (q3 shr 16) or (q3 shl 48)
    let r4 = (q4 shr 16) or (q4 shl 48)
    let r5 = (q5 shr 16) or (q5 shl 48)
    let r6 = (q6 shr 16) or (q6 shl 48)
    let r7 = (q7 shr 16) or (q7 shl 48)
    let v0 = q0 xor r0
    let v1 = q1 xor r1
    let v2 = q2 xor r2
    let v3 = q3 xor r3
    let v4 = q4 xor r4
    let v5 = q5 xor r5
    let v6 = q6 xor r6
    let v7 = q7 xor r7

    q[0] = q7 xor r7 xor r0 xor rotr32(v0)
    q[1] = q0 xor r0 xor q7 xor r7 xor r1 xor rotr32(v1)
    q[2] = q1 xor r1 xor r2 xor rotr32(v2)
    q[3] = q2 xor r2 xor q7 xor r7 xor r3 xor rotr32(v3)
    q[4] = q3 xor r3 xor q7 xor r7 xor r4 xor rotr32(v4)
    q[5] = q4 xor r4 xor r5 xor rotr32(v5)
    q[6] = q5 xor r5 xor r6 xor rotr32(v6)
    q[7] = q6 xor r6 xor r7 xor rotr32(v7)

  template invMixColumns(q: untyped) =
    let q0 = q[0]
    let q1 = q[1]
    let q2 = q[2]
    let q3 = q[3]
    let q4 = q[4]
    let q5 = q[5]
    let q6 = q[6]
    let q7 = q[7]
    let r0 = (q0 shr 16) or (q0 shl 48)
    let r1 = (q1 shr 16) or (q1 shl 48)
    let r2 = (q2 shr 16) or (q2 shl 48)
    let r3 = (q3 shr 16) or (q3 shl 48)
    let r4 = (q4 shr 16) or (q4 shl 48)
    let r5 = (q5 shr 16) or (q5 shl 48)
    let r6 = (q6 shr 16) or (q6 shl 48)
    let r7 = (q7 shr 16) or (q7 shl 48)
    let v0 = q0 xor q5 xor q6 xor r0 xor r5
    let v1 = q1 xor q5 xor q7 xor r1 xor r5 xor r6
    let v2 = q0 xor q2 xor q6 xor r2 xor r6 xor r7
    let v3 = q0 xor q1 xor q3 xor q5 xor q6 xor q7 xor r0 xor r3 xor r5 xor r7
    let v4 = q1 xor q2 xor q4 xor q5 xor q7 xor r1 xor r4 xor r5 xor r6
    let v5 = q2 xor q3 xor q5 xor q6 xor r2 xor r5 xor r6 xor r7
    let v6 = q3 xor q4 xor q6 xor q7 xor r3 xor r6 xor r7
    let v7 = q4 xor q5 xor q7 xor r4 xor r7
    q[0] = q5 xor q6 xor q7 xor r0 xor r5 xor r7 xor rotr32(v0)
    q[1] = q0 xor q5 xor r0 xor r1 xor r5 xor r6 xor r7 xor rotr32(v1)
    q[2] = q0 xor q1 xor q6 xor r1 xor r2 xor r6 xor r7 xor rotr32(v2)
    q[3] = q0 xor q1 xor q2 xor q5 xor q6 xor r0 xor r2 xor r3 xor r5 xor
           rotr32(v3)
    q[4] = q1 xor q2 xor q3 xor q5 xor r1 xor r3 xor r4 xor r5 xor r6 xor
           r7 xor rotr32(v4)
    q[5] = q2 xor q3 xor q4 xor q6 xor r2 xor r4 xor r5 xor r6 xor r7 xor
           rotr32(v5)
    q[6] = q3 xor q4 xor q5 xor q7 xor r3 xor r5 xor r6 xor r7 xor rotr32(v6)
    q[7] = q4 xor q5 xor q6 xor r4 xor r6 xor r7 xor rotr32(v7)

  proc encrypt*(ctx: RijndaelContext, input: openArray[byte],
                output: var openArray[byte]) =
    var q: array[8, uint64]
    var w: array[4, uint32]

    w[0] = leLoad32(input, 0)
    w[1] = leLoad32(input, 4)
    w[2] = leLoad32(input, 8)
    w[3] = leLoad32(input, 12)

    interleaveIn(q[0], q[4], w)
    ortho(q)

    addRoundKey(q, ctx.skey, 0)
    for u in 1 ..< ctx.nr:
      bitsliceSbox(q)
      shiftRows(q)
      mixColumns(q)
      let offset = u shl 3
      addRoundKey(q, ctx.skey, offset)

    bitsliceSbox(q)
    shiftRows(q)
    let offset = ctx.nr shl 3
    addRoundKey(q, ctx.skey, offset)

    ortho(q)
    interleaveOut(w, q[0], q[4])

    leStore32(output, 0, w[0])
    leStore32(output, 4, w[1])
    leStore32(output, 8, w[2])
    leStore32(output, 12, w[3])

  proc decrypt*(ctx: RijndaelContext, input: openArray[byte],
                output: var openArray[byte]) =
    var q: array[8, uint64]
    var w: array[16, uint32]

    w[0] = leLoad32(input, 0)
    w[1] = leLoad32(input, 4)
    w[2] = leLoad32(input, 8)
    w[3] = leLoad32(input, 12)

    interleaveIn(q[0], q[4], w.toOpenArray(0, 3))
    interleaveIn(q[1], q[5], w.toOpenArray(4, 7))
    interleaveIn(q[2], q[6], w.toOpenArray(8, 11))
    interleaveIn(q[3], q[7], w.toOpenArray(12, 15))

    ortho(q)
    let offset = ctx.nr shl 3
    addRoundKey(q, ctx.skey, offset)
    for u in countdown(ctx.nr - 1, 1):
      invShiftRows(q)
      bitsliceInvSbox(q)
      let offset = u shl 3
      addRoundKey(q, ctx.skey, offset)
      invMixColumns(q)

    invShiftRows(q)
    bitsliceInvSbox(q)
    addRoundKey(q, ctx.skey, 0)
    ortho(q)

    interleaveOut(w.toOpenArray(0, 3), q[0], q[4])
    interleaveOut(w.toOpenArray(4, 7), q[1], q[5])
    interleaveOut(w.toOpenArray(8, 11), q[2], q[6])
    interleaveOut(w.toOpenArray(12, 15), q[3], q[7])

    leStore32(output, 0, w[0])
    leStore32(output, 4, w[1])
    leStore32(output, 8, w[2])
    leStore32(output, 12, w[3])

template sizeKey*(ctx: RijndaelContext): int =
  (ctx.bits div 8)

template sizeBlock*(ctx: RijndaelContext): int =
  (16)

template sizeKey*(r: typedesc[rijndael]): int =
  when r is aes128 or r is rijndael128:
    (16)
  elif r is aes192 or r is rijndael192:
    (24)
  elif r is aes256 or r is rijndael256:
    (32)

template sizeBlock*(r: typedesc[rijndael]): int =
  (16)

proc init*(ctx: var RijndaelContext, key: openArray[byte]) {.inline.} =
  keySchedule(ctx, key)

proc init*(ctx: var RijndaelContext, key: ptr byte, nkey: int = 0) {.inline.} =
  var p = cast[ptr UncheckedArray[byte]](key)
  keySchedule(ctx, toOpenArray(p, 0, int(ctx.sizeKey()) - 1))

proc clear*(ctx: var RijndaelContext) {.inline.} =
  burnMem(ctx)

proc encrypt*(ctx: var RijndaelContext, inbytes: ptr byte,
              outbytes: ptr byte) {.inline.} =
  var ip = cast[ptr UncheckedArray[byte]](inbytes)
  var op = cast[ptr UncheckedArray[byte]](outbytes)
  encrypt(ctx, toOpenArray(ip, 0, ctx.sizeBlock() - 1),
               toOpenArray(op, 0, ctx.sizeBlock() - 1))

proc decrypt*(ctx: var RijndaelContext, inbytes: ptr byte,
              outbytes: ptr byte) {.inline.} =
  var ip = cast[ptr UncheckedArray[byte]](inbytes)
  var op = cast[ptr UncheckedArray[byte]](outbytes)
  decrypt(ctx, toOpenArray(ip, 0, ctx.sizeBlock() - 1),
               toOpenArray(op, 0, ctx.sizeBlock() - 1))
