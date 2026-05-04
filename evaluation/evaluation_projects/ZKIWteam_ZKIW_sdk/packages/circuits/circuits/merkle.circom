// Simple Merkle Membership Proof Verifier
// Assumes binary tree, depth 8, left path (pathIndices = 0)
pragma circom 2.0.0;
include "poseidon.circom";

template MerkleVerifier(depth) {
    signal input root;
    signal input leaf;
    signal input pathElements[depth];
    // signal input pathIndices[depth]; // Assume left path for simplicity

    component poseidon[depth];
    signal current[depth+1];
    current[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        poseidon[i] = Poseidon(2);
        poseidon[i].inputs[0] <== current[i];
        poseidon[i].inputs[1] <== pathElements[i];
        current[i+1] <== poseidon[i].out;
    }

    root === current[depth];
}