pragma circom 2.1.5;

include "circomlib/circuits/escalarmulfix.circom";
include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/bitify.circom";

// Exponential ElGamal Encryption on BabyJubJub
// Ciphertext = (C1, C2) = (r*G, r*PK + m*G)
template ElGamal() {
    signal input pk[2];    // Public Key (Point)
    signal input r;        // Randomness (Scalar)
    signal input m;        // Message (Scalar)

    signal output c1[2];   // C1 = r * G
    signal output c2[2];   // C2 = r * PK + m * G

    // Generator G (Base8)
    var Gx = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    var Gy = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    // Convert r to bits
    component rBits = Num2Bits(253);
    rBits.in <== r;

    // C1 = r * G
    component mulG = EscalarMulFix(253, [Gx, Gy]);
    for (var i = 0; i < 253; i++) {
        mulG.e[i] <== rBits.out[i];
    }
    c1[0] <== mulG.out[0];
    c1[1] <== mulG.out[1];

    // r * PK
    component mulPK = EscalarMulAny(253);
    mulPK.p[0] <== pk[0];
    mulPK.p[1] <== pk[1];
    for (var i = 0; i < 253; i++) {
        mulPK.e[i] <== rBits.out[i];
    }

    // m * G
    component mBits = Num2Bits(253);
    mBits.in <== m;
    
    component mulM = EscalarMulFix(253, [Gx, Gy]);
    for (var i = 0; i < 253; i++) {
        mulM.e[i] <== mBits.out[i];
    }

    // C2 = r*PK + m*G
    component add = BabyAdd();
    add.x1 <== mulPK.out[0];
    add.y1 <== mulPK.out[1];
    add.x2 <== mulM.out[0];
    add.y2 <== mulM.out[1];
    
    c2[0] <== add.xout;
    c2[1] <== add.yout;
}
