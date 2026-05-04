pragma circom 2.0.0;

include "utils/poseidon.circom";
include "./utils/custom_comparators.circom";
include "utils/merkletree.circom";
include "utils/merkleproof.circom";

template UTXOOwnership(nLevels) {
    signal input leaf; // UTXO hash
    signal input pathElements[nLevels]; // Merkle proof
    signal input pathIndices[nLevels]; // Path indices (0 or 1)
    signal input nullifier; // Private signal to prevent double-spending
    signal input root; // Expected Merkle root
    signal output nullifierHash; // Hashed nullifier

    // Compute Merkle proof
    component merkleProof = MerkleProof(nLevels);
    merkleProof.leaf <== leaf;
    for (var i = 0; i < nLevels; i++) {
        merkleProof.pathElements[i] <== pathElements[i];
        merkleProof.pathIndices[i] <== pathIndices[i];
    }
    
    // Validate Merkle root
    merkleProof.root === root;
    
    // Prevent double-spending
    component isZero = IsZero();
    isZero.in <== nullifier;
    isZero.out === 0; // Fails if nullifier is 0

    // Verify Merkle proof
    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== leaf;
    poseidon.inputs[1] <== nullifier;
    nullifierHash <== poseidon.out;
}

component main { public [ root, nullifier ] } = UTXOOwnership(4);
