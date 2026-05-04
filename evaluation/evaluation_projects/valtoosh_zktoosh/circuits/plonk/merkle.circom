pragma circom 2.1.8;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";

/*
 * Phase 6C: Merkle Tree Inclusion Proof
 * Proves that a leaf exists in a Merkle tree without revealing which leaf
 * This creates an anonymity set for pending transfers
 */

/**
 * Merkle Tree Inclusion Proof
 * @param levels - Number of levels in the tree (20 = ~1M capacity)
 */
template MerkleTreeInclusionProof(levels) {
    signal input leaf;                      // Leaf to prove inclusion for
    signal input root;                      // Merkle root (public)
    signal input pathElements[levels];      // Sibling hashes along the path
    signal input pathIndices[levels];       // 0 = left sibling, 1 = right sibling

    signal output isValid;                  // 1 if proof is valid

    // Hash computation from leaf to root
    component hashers[levels];
    component muxes[levels];

    signal hashes[levels + 1];
    hashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // Select left and right inputs based on path index
        // If pathIndices[i] == 0: current hash is left, sibling is right
        // If pathIndices[i] == 1: sibling is left, current hash is right

        muxes[i] = MultiMux1(2);
        muxes[i].c[0][0] <== hashes[i];
        muxes[i].c[0][1] <== pathElements[i];
        muxes[i].c[1][0] <== pathElements[i];
        muxes[i].c[1][1] <== hashes[i];
        muxes[i].s <== pathIndices[i];

        // Hash parent node
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== muxes[i].out[0];
        hashers[i].inputs[1] <== muxes[i].out[1];

        hashes[i + 1] <== hashers[i].out;
    }

    // Check if computed root matches provided root
    component rootCheck = IsEqual();
    rootCheck.in[0] <== hashes[levels];
    rootCheck.in[1] <== root;

    isValid <== rootCheck.out;
}

/**
 * Merkle Tree Leaf Hash
 * Computes the leaf hash for a pending transfer
 */
template MerkleLeafHash() {
    signal input recipientHash;      // Hash of recipient
    signal input transferAmount;     // Transfer amount
    signal input timestamp;          // Transfer timestamp

    signal output leafHash;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== recipientHash;
    hasher.inputs[1] <== transferAmount;
    hasher.inputs[2] <== timestamp;

    leafHash <== hasher.out;
}
