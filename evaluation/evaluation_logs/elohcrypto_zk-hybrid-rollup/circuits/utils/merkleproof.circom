pragma circom 2.0.0;

include "./poseidon.circom";

template MerkleProof(nLevels) {
    signal input leaf;
    signal input pathElements[nLevels];
    signal input pathIndices[nLevels];
    signal output root;

    component poseidon[nLevels];
    signal levelHashes[nLevels + 1];
    levelHashes[0] <== leaf;

    // Declare signals outside the loop
    signal leftInput[nLevels];
    signal rightInput[nLevels];
    for (var i = 0; i < nLevels; i++) {
        poseidon[i] = Poseidon(2);
        // Select left and right inputs based on pathIndices[i]
        leftInput[i] <== pathIndices[i] * (pathElements[i] - levelHashes[i]) + levelHashes[i];
        rightInput[i] <== (1 - pathIndices[i]) * (pathElements[i] - levelHashes[i]) + levelHashes[i];
        poseidon[i].inputs[0] <== leftInput[i];
        poseidon[i].inputs[1] <== rightInput[i];
        levelHashes[i + 1] <== poseidon[i].out;
    }

    root <== levelHashes[nLevels];
}