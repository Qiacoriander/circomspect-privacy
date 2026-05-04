pragma circom 2.1.8;
include "../helper.circom";
include "../circom-ecdsa/ecdsa.circom";
include "bigInt.circom";

template IsPKValid() {
    signal input pk[2][4];
    signal output out;

    signal mod[4];

    // secp256k1's prime number
    // FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
    mod[3] <== 0xFFFFFFFFFFFFFFFF;
    mod[2] <== 0xFFFFFFFFFFFFFFFF;
    mod[1] <== 0xFFFFFFFFFFFFFFFF;
    mod[0] <== 0xFFFFFFFEFFFFFC2F;

    signal x[4][4];
    x[1] <== pk[0];
    for (var i = 2; i < 4; i++)
        x[i] <== mult_mod(4, 64)(x[i - 1], x[1], mod);

    signal y[3][4];
    y[1] <== pk[1];
    for (var i = 2; i < 3; i++)
        y[i] <== mult_mod(4, 64)(y[i - 1], y[1], mod);

    signal RHS_raw[4]; // x^3 + 7 without mod
    for (var i = 0; i < 4; i++)
        RHS_raw[i] <== x[3][i] + (i == 0 ? 7 : 0);

    signal RHS[4] <== sub_if_ge(4, 64)(RHS_raw, mod);
    out <== long_equals(4)(y[2], RHS);
}

template CheckSignature() {
    // 4x64 bits each
    signal input r[4];
    signal input s[4];
    // x, y, 4x64 bits each
    signal input pk[2][4];

    signal input msgHash[4];

    signal output out;

    var CHECKS = 7;
    signal check[CHECKS];
    check[0] <== CheckRepr()(r);
    check[1] <== CheckRepr()(s);
    check[2] <== CheckRepr()(pk[0]);
    check[3] <== CheckRepr()(pk[1]);
    check[4] <== CheckRepr()(msgHash);
    check[5] <== IsPKValid()(pk);
    check[6] <== ECDSAVerifyNoPubkeyCheck(64, 4)(r, s, msgHash, pk);

    out <== All(CHECKS)(check);
}
