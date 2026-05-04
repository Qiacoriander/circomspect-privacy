pragma circom 2.1.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/escalarmulfix.circom";

/*
    ElGamalC1 is a circuit that constrains the first part of the ElGamal encryption scheme.
    It takes as input a random number.
    It outputs randomness * BASE8
*/
template ElGamalC1() {
    signal input random_bits[253];
    signal output out[2];

    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];
    // r * BASE8
    signal rG[2] <== EscalarMulFix(253, BASE8)(e <== random_bits);

    out <== rG;
}