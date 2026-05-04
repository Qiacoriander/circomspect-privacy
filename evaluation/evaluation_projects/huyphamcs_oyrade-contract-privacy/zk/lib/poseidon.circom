// Poseidon hash wrappers.
// These are thin wrappers around circomlib's Poseidon implementation.
//
// IMPORTANT: You must have `circomlib` installed and make sure the include
// path below matches your environment. Adjust if necessary.
//
//   npm install circomlib
//
// and invoke circom with:
//   circom -l node_modules ...

pragma circom 2.1.4;

include "circomlib/circuits/poseidon.circom";

// Two-input Poseidon hash (same parameters as Solana's Bn254X5 Poseidon).
template Poseidon2() {
    signal input in[2];
    signal output out;

    component h = Poseidon(2);
    h.inputs[0] <== in[0];
    h.inputs[1] <== in[1];
    out <== h.out;
}

// Three-input Poseidon hash.
template Poseidon3() {
    signal input in[3];
    signal output out;

    component h = Poseidon(3);
    for (var i = 0; i < 3; i++) {
        h.inputs[i] <== in[i];
    }
    out <== h.out;
}

