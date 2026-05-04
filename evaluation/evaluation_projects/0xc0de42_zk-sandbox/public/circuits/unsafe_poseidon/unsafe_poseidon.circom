pragma circom 2.1.8;

include "comparators.circom";
include "poseidon.circom";

/*
The issue with code, is as follows:

Circom field elements are exist in the field, p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
Circom cannot handle values larger than p, as they would "wrap around".

p takes 254 bits to store, but the value of (2²⁵⁴ - 1) > p.
Meaning to say, 254 bits can encode numbers larger than circom signals can store,
leading to the situation where there might be more than 1 valid witness in the range [p, 2²⁵⁴ - 1];

Fix
To fix the issue one should use Num2Bits_strict instead of Num2Bits (and Bits2Num).

*/

template UnsafePoseidon(n) {
    signal input in;
    signal output out;

    component n2b = Num2Bits(n);
    component b2n = Bits2Num(n);
    component phash = Poseidon(1);

    n2b.in <== in;
    for (var i = 0; i < n; i++) {
        b2n.in[i] <== n2b.out[i];
    }

    phash.inputs[0] <== b2n.out;
    phash.out ==> out;
}

component main = UnsafePoseidon(254);