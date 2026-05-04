pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/**
 * Contributor Proof Circuit
 * 
 * This circuit proves that a contributor is registered without revealing their identity.
 * 
 * Public Inputs:
 *   - commitment: Hash of (address, nonce) - identifies this submission
 *   - merkleRoot: Root of contributor Merkle tree
 * 
 * Private Inputs:
 *   - address: Contributor's Ethereum address
 *   - nonce: Random value for commitment
 *   - merkleProof: Proof that address is in contributor tree
 *   - merklePathIndices: Path indices for Merkle proof
 * 
 * Proves:
 *   1. commitment = Poseidon(address, nonce)
 *   2. address exists in Merkle tree with root merkleRoot
 *   3. Without revealing actual address
 */

template MerkleTreeInclusionProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output root;

    component hashers[levels];
    component mux[levels];

    signal levelHashes[levels + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        // Select left/right based on path index
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        hashers[i] = Poseidon(2);
        mux[i] = MultiMux1(2);

        mux[i].c[0][0] <== levelHashes[i];
        mux[i].c[0][1] <== pathElements[i];
        mux[i].c[1][0] <== pathElements[i];
        mux[i].c[1][1] <== levelHashes[i];

        mux[i].s <== pathIndices[i];

        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];

        levelHashes[i + 1] <== hashers[i].out;
    }

    root <== levelHashes[levels];
}

template MultiMux1(n) {
    signal input c[n][2];
    signal input s;
    signal output out[n];

    for (var i = 0; i < n; i++) {
        out[i] <== c[i][0] + s * (c[i][1] - c[i][0]);
    }
}

template ContributorProof(merkleTreeLevels) {
    // Public inputs (visible on-chain)
    signal input commitment;
    signal input merkleRoot;

    // Private inputs (hidden)
    signal input address;
    signal input nonce;
    signal input merkleProof[merkleTreeLevels];
    signal input merklePathIndices[merkleTreeLevels];

    // Verify commitment = Poseidon(address, nonce)
    component commitmentHasher = Poseidon(2);
    commitmentHasher.inputs[0] <== address;
    commitmentHasher.inputs[1] <== nonce;
    commitment === commitmentHasher.out;

    // Verify address is in Merkle tree
    // NOTE: The Poseidon contributor tree stores leaves as Poseidon([address]).
    // This matches `scripts/auto-rebuild-poseidon-tree.js` which computes
    // `leaves[i] = Poseidon([addressBigInt])` and then builds the tree with Poseidon(2).
    // Therefore the circuit must hash the private `address` into the leaf.
    component leafHasher = Poseidon(1);
    leafHasher.inputs[0] <== address;

    component merkleChecker = MerkleTreeInclusionProof(merkleTreeLevels);
    merkleChecker.leaf <== leafHasher.out;
    for (var i = 0; i < merkleTreeLevels; i++) {
        merkleChecker.pathElements[i] <== merkleProof[i];
        merkleChecker.pathIndices[i] <== merklePathIndices[i];
    }
    merkleRoot === merkleChecker.root;

    // Constraint: address must be non-zero (valid Ethereum address)
    component isZero = IsZero();
    isZero.in <== address;
    isZero.out === 0;
}

// Instantiate with 20 levels (supports up to 2^20 = 1,048,576 contributors)
component main {public [commitment, merkleRoot]} = ContributorProof(20);
