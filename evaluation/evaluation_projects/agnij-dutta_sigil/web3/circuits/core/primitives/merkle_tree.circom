pragma circom 2.0.0;

include "../utilities.circom";
include "circomlib/circuits/poseidon.circom";

/*
 * Merkle Tree Verification Circuit
 * Verifies that a leaf is included in a Merkle tree
 */
template MerkleTreeVerifier(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal input root;
    
    signal output valid;
    
    component hashers[levels];
    component mux[levels];
    
    signal levelHashes[levels + 1];
    levelHashes[0] <== leaf;
    
    for (var i = 0; i < levels; i++) {
        // Select which input to hash first based on path index
        mux[i] = Mux1();
        mux[i].c[0] <== levelHashes[i];
        mux[i].c[1] <== pathElements[i];
        mux[i].s <== pathIndices[i];
        
        // Hash the pair
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out;
        hashers[i].inputs[1] <== pathElements[i];
        
        levelHashes[i + 1] <== hashers[i].out;
    }
    
    // Check if computed root matches expected root
    component rootCheck = IsEqual();
    rootCheck.in[0] <== levelHashes[levels];
    rootCheck.in[1] <== root;
    
    valid <== rootCheck.out;
}

/*
 * Merkle Tree Inclusion Proof with Privacy
 * Proves inclusion without revealing the exact position
 */
template PrivateMerkleTreeInclusionProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal input root;
    signal input nullifier;        // Unique nullifier for this proof
    signal input nullifierSecret;  // Secret used to generate nullifier
    
    signal output nullifierHash;   // Hash of nullifier + secret
    signal output valid;
    
    // Verify the Merkle tree inclusion
    component merkleVerifier = MerkleTreeVerifier(levels);
    merkleVerifier.leaf <== leaf;
    for (var i = 0; i < levels; i++) {
        merkleVerifier.pathElements[i] <== pathElements[i];
        merkleVerifier.pathIndices[i] <== pathIndices[i];
    }
    merkleVerifier.root <== root;
    
    valid <== merkleVerifier.valid;
    
    // Generate nullifier hash to prevent double-spending
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== nullifier;
    nullifierHasher.inputs[1] <== nullifierSecret;
    
    nullifierHash <== nullifierHasher.out;
}

/*
 * Sparse Merkle Tree Operations
 */
template SparseMerkleTreeVerifier(levels) {
    signal input key;
    signal input value;
    signal input siblings[levels];
    signal input keyBits[levels];
    signal input root;
    
    signal output valid;
    
    component hashers[levels + 1];
    component leftMux[levels];
    component rightMux[levels];
    
    component leafHasher = Poseidon(2);
    leafHasher.inputs[0] <== key;
    leafHasher.inputs[1] <== value;
    
    signal levelHashes[levels + 1];
    levelHashes[0] <== leafHasher.out;
    
    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);
        
        // Choose left or right based on key bit
        leftMux[i] = Mux1();
        leftMux[i].c[0] <== levelHashes[i];
        leftMux[i].c[1] <== siblings[i];
        leftMux[i].s <== keyBits[i];
        
        rightMux[i] = Mux1();
        rightMux[i].c[0] <== siblings[i];
        rightMux[i].c[1] <== levelHashes[i];
        rightMux[i].s <== keyBits[i];
        
        hashers[i].inputs[0] <== leftMux[i].out;
        hashers[i].inputs[1] <== rightMux[i].out;
        
        levelHashes[i + 1] <== hashers[i].out;
    }
    
    component rootCheck = IsEqual();
    rootCheck.in[0] <== levelHashes[levels];
    rootCheck.in[1] <== root;
    
    valid <== rootCheck.out;
}

component main = MerkleTreeVerifier(20);
