pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/babyjub.circom";
include "../node_modules/circomlib/circuits/escalarmulany.circom";

template Vote(n) {
    assert(n<253);
    signal input publicKey[2];
    signal input c1[2];
    signal input c2[2];
    signal input m[2];
    signal input randomK;

    signal isInRange <== LessThan(n)([randomK, 2736030358979909402780800718157159386076813972158567259200215660948447373041]);
    isInRange === 1;

    component k = Num2Bits(n);
    k.in <== randomK;

    component kMulG = EscalarMulFix(n, [5299619240641551281634865583518297030282874472190772894086521144482721001553, 16950150798460657717958625567821834550301663161624707787222815936182638968203]);
    kMulG.e <== k.out;

    component kMulPublickey = EscalarMulAny(n);
    kMulPublickey.e <== k.out;
    kMulPublickey.p <== publicKey;

    component calculateC2 = BabyAdd();
    calculateC2.x1 <== m[0];
    calculateC2.y1 <== m[1];
    calculateC2.x2 <== kMulPublickey.out[0];
    calculateC2.y2 <== kMulPublickey.out[1];

    kMulG.out === c1;
    calculateC2.xout === c2[0];
    calculateC2.yout === c2[1];
}

component main {public [publicKey, c1, c2]} = Vote(252);
