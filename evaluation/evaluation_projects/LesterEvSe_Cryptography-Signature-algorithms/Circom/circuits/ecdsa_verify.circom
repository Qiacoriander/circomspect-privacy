pragma circom 2.1.6;

include "../ecdsa/secp256r1/p256.circom";

template EcdsaVerify(BITS, BLOCKS) {
    signal input message[BLOCKS];
    signal input sign[2][BLOCKS];
    signal input pubkey[2][BLOCKS];
    signal output IsVerified;

    // secp256r1
    signal e[BLOCKS] <== [65537, 0, 0, 0, 0, 0];
    signal order[BLOCKS] <== [3036481267025, 3246200354617, 7643362670236, 8796093022207, 1048575, 2199023255040];
    signal G[2][BLOCKS] <== [
        [1399498261142, 5937592964135, 2044638659767, 3791144493177, 3041449184206, 919922271682],
        [447611884021, 6785408267976, 752572259756, 6207268441867, 1820960812670, 686230455804]
    ];

    component w = BigModInv(BITS, BLOCKS);
    w.in <== sign[1];
    w.p <== order;

    // u1 = (e * w) % order
    component u1 = BigMultModP(BITS, BLOCKS);
    u1.a <== e;
    u1.b <== w.out;
    u1.p <== order;

    // u2 = (sign[0] * w) % order
    component u2 = BigMultModP(BITS, BLOCKS);
    u2.a <== sign[0];
    u2.b <== w.out;
    u2.p <== order;

    // R = u1*G + u2*sign
    component u1G = P256GeneratorMultiplication(BITS, BLOCKS);
    u1G.scalar <== u1.out;
    // u1G.point <== G;

    component u2Q = P256ScalarMult(BITS, BLOCKS);
    u2Q.scalar <== u2.out;
    u2Q.point <== pubkey;

    component R = P256AddUnequal(BITS, BLOCKS);
    R.point1 <== u1G.out;
    R.point2 <== u2Q.out;

    // R[0] % order == sign[0]
    signal one[BLOCKS] <== [1, 0, 0, 0, 0, 0];
    component r = BigMultModP(BITS, BLOCKS);
    r.a <== R.out[0];
    r.b <== one;
    r.p <== order;

    r.out === sign[0];
    IsVerified <== 1;
}

component main {public [pubkey]} = EcdsaVerify(43, 6);