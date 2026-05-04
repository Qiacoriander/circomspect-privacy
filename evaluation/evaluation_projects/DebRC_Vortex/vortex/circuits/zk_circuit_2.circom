pragma circom 2.0.0;
include "circomlib/circuits/poseidon.circom";

template ZKProof2(levels) {
    // Private inputs
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    // Public output: the computed Merkle root
    signal output root;

    // Internal signals
    component hashers[levels];
    signal intermediate[levels + 1];

    // To avoid “sum of products” in one constraint:
    signal leftA[levels];
    signal leftB[levels];
    signal leftSig[levels];
    signal rightA[levels];
    signal rightB[levels];
    signal rightSig[levels];

    // Initialize
    intermediate[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // 1) Instantiate Poseidon hasher
        hashers[i] = Poseidon(2);

        // 2) Compute branches in two separate multiplications each
        // leftA = (1 - idx) * previousHash
        leftA[i]  <== (1 - pathIndices[i]) * intermediate[i];
        // leftB = idx * pathElement
        leftB[i]  <== pathIndices[i] * pathElements[i];
        // leftSig = leftA + leftB  (linear add)
        leftSig[i] <== leftA[i] + leftB[i];

        // rightA = idx * previousHash
        rightA[i] <== pathIndices[i] * intermediate[i];
        // rightB = (1 - idx) * pathElement
        rightB[i] <== (1 - pathIndices[i]) * pathElements[i];
        // rightSig = rightA + rightB
        rightSig[i] <== rightA[i] + rightB[i];

        // 3) Hash the two branches
        hashers[i].inputs[0] <== leftSig[i];
        hashers[i].inputs[1] <== rightSig[i];
        intermediate[i + 1]    <== hashers[i].out;
    }

    // 4) Expose the final computed root
    root <== intermediate[levels];
}

component main = ZKProof2(50);

// Gas Cost - 200K