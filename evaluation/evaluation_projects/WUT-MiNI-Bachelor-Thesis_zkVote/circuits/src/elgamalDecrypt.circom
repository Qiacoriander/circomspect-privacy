pragma circom 2.1.5;

include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/escalarmulfix.circom";
include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/bitify.circom";

// Prove correct decryption of a single ElGamal ciphertext
// without revealing the secret key
// 
// Given: pk, c1, c2, m (decrypted message as scalar)
// Proves: pk = sk * G  AND  m * G = c2 - sk * c1
template ElGamalDecrypt() {
    // Generator G (Base8)
    var Gx = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    var Gy = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    // --- Public inputs ---
    signal input pk[2];     // Public key (EC Point)
    signal input c1[2];     // Ciphertext part 1 (EC Point)
    signal input c2[2];     // Ciphertext part 2 (EC Point)
    signal input m;         // Decrypted message (scalar)

    // --- Private inputs ---
    signal input sk;        // Secret key

    // --- 1. Verify pk = sk * G ---
    component skBits = Num2Bits(253);
    skBits.in <== sk;

    component skG = EscalarMulFix(253, [Gx, Gy]);
    for (var i = 0; i < 253; i++) {
        skG.e[i] <== skBits.out[i];
    }
    pk[0] === skG.out[0];
    pk[1] === skG.out[1];

    // --- 2. Compute sk * c1 ---
    component skC1 = EscalarMulAny(253);
    skC1.p[0] <== c1[0];
    skC1.p[1] <== c1[1];
    for (var i = 0; i < 253; i++) {
        skC1.e[i] <== skBits.out[i];
    }

    // --- 3. Compute m * G ---
    component mBits = Num2Bits(253);
    mBits.in <== m;
    
    component mG = EscalarMulFix(253, [Gx, Gy]);
    for (var i = 0; i < 253; i++) {
        mG.e[i] <== mBits.out[i];
    }

    // --- 4. Verify m * G = c2 - sk * c1 ---
    // Subtraction: c2 + (-skC1) where -P = (-x, y) in twisted Edwards
    component subtract = BabyAdd();
    subtract.x1 <== c2[0];
    subtract.y1 <== c2[1];
    subtract.x2 <== 0 - skC1.out[0];  // Negate x
    subtract.y2 <== skC1.out[1];

    subtract.xout === mG.out[0];
    subtract.yout === mG.out[1];
}
