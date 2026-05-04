pragma circom 2.1.0;

include "poseidon.circom";

// Selector component for Merkle tree path
// If pathIndex == 0, output (in, sibling) - in is on the left
// If pathIndex == 1, output (sibling, in) - in is on the right
template DualMux() {
    signal input in;
    signal input sibling;
    signal input pathIndex;
    signal output left;
    signal output right;

    // Ensure pathIndex is binary (0 or 1)
    pathIndex * (1 - pathIndex) === 0;

    // Select based on pathIndex using intermediate signals for quadratic constraints
    // If pathIndex == 0: left = in, right = sibling
    // If pathIndex == 1: left = sibling, right = in

    // Compute: sibling * pathIndex
    signal siblingTimesIndex;
    siblingTimesIndex <== sibling * pathIndex;

    // Compute: in * pathIndex
    signal inTimesIndex;
    inTimesIndex <== in * pathIndex;

    // left = sibling * pathIndex + in * (1 - pathIndex) = sibling * pathIndex + in - in * pathIndex
    left <== siblingTimesIndex + in - inTimesIndex;

    // right = in * pathIndex + sibling * (1 - pathIndex) = in * pathIndex + sibling - sibling * pathIndex
    right <== inTimesIndex + sibling - siblingTimesIndex;
}

// Merkle tree inclusion proof verifier
// depth: number of levels in the tree (e.g., 20 for ~1M leaves)
template MerkleTreeVerifier(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal input root;

    component hashers[depth];
    component mux[depth];

    signal levelHashes[depth + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        mux[i] = DualMux();
        mux[i].in <== levelHashes[i];
        mux[i].sibling <== pathElements[i];
        mux[i].pathIndex <== pathIndices[i];

        hashers[i] = PoseidonMerkle();
        hashers[i].left <== mux[i].left;
        hashers[i].right <== mux[i].right;

        levelHashes[i + 1] <== hashers[i].out;
    }

    // Verify computed root matches expected root
    root === levelHashes[depth];
}

// Compute Merkle root from leaf and path
// Returns the computed root (doesn't constrain it)
template MerkleTreeCompute(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    signal output computedRoot;

    component hashers[depth];
    component mux[depth];

    signal levelHashes[depth + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        mux[i] = DualMux();
        mux[i].in <== levelHashes[i];
        mux[i].sibling <== pathElements[i];
        mux[i].pathIndex <== pathIndices[i];

        hashers[i] = PoseidonMerkle();
        hashers[i].left <== mux[i].left;
        hashers[i].right <== mux[i].right;

        levelHashes[i + 1] <== hashers[i].out;
    }

    computedRoot <== levelHashes[depth];
}

// Note: IsZero and IsEqual are available from circomlib/circuits/comparators.circom
// Include that file if you need these utilities
