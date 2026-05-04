pragma circom 2.1.5;

include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/escalarmulfix.circom";
include "circomlib/circuits/bitify.circom";

// Pedersen Commitment: C = vote * G + blinder * H
template PedersenCommitment() {
    signal input vote;      // 0 or 1
    signal input blinder;   // random scalar (< subgroup order)
    signal output out[2];   // commitment point (x, y)

    // Generator G (Base8 - standard BabyJubJub generator)
    var Gx = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    var Gy = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

    // Generator H (independent NUMS point)
    var Hx = 17777552123799933955779906779655732241715742912184938656739573121738514868268;
    var Hy = 2626589144620713026669568689430873010625803728049924121243784502389097019475;

    // Convert blinder to bits for scalar multiplication
    component blinderBits = Num2Bits(253);
    blinderBits.in <== blinder;

    // Convert vote to bits
    component voteBits = Num2Bits(253);
    voteBits.in <== vote;

    // Compute vote * G using EscalarMulFix
    component voteG = EscalarMulFix(253, [Gx, Gy]);
    for (var i = 0; i < 253; i++) {
        voteG.e[i] <== voteBits.out[i];
    }

    // Compute blinder * H using EscalarMulFix
    component blinderH = EscalarMulFix(253, [Hx, Hy]);
    for (var i = 0; i < 253; i++) {
        blinderH.e[i] <== blinderBits.out[i];
    }

    // Add: vote*G + blinder*H
    component add = BabyAdd();
    add.x1 <== voteG.out[0];
    add.y1 <== voteG.out[1];
    add.x2 <== blinderH.out[0];
    add.y2 <== blinderH.out[1];

    out[0] <== add.xout;
    out[1] <== add.yout;
}
