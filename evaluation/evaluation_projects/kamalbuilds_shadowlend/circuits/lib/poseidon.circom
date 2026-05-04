pragma circom 2.1.0;

// Include Poseidon from circomlib
include "circomlib/circuits/poseidon.circom";

// Wrapper template for 2-input Poseidon hash
// Used for computing commitments: commitment = Poseidon(nullifier, amount)
template PoseidonHash2() {
    signal input in[2];
    signal output out;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== in[0];
    hasher.inputs[1] <== in[1];

    out <== hasher.out;
}

// Wrapper template for 3-input Poseidon hash
// Useful for more complex commitments
template PoseidonHash3() {
    signal input in[3];
    signal output out;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== in[0];
    hasher.inputs[1] <== in[1];
    hasher.inputs[2] <== in[2];

    out <== hasher.out;
}

// Wrapper template for 4-input Poseidon hash
template PoseidonHash4() {
    signal input in[4];
    signal output out;

    component hasher = Poseidon(4);
    hasher.inputs[0] <== in[0];
    hasher.inputs[1] <== in[1];
    hasher.inputs[2] <== in[2];
    hasher.inputs[3] <== in[3];

    out <== hasher.out;
}

// Poseidon hash for Merkle tree nodes
// Takes left and right children, outputs parent hash
template PoseidonMerkle() {
    signal input left;
    signal input right;
    signal output out;

    component hasher = Poseidon(2);
    hasher.inputs[0] <== left;
    hasher.inputs[1] <== right;

    out <== hasher.out;
}
