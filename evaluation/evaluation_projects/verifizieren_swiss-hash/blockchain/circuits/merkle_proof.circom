pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";

// File commitment template using Poseidon hash
template FileCommitment() {
    // Private inputs: file hash (split into two field elements for SHA256 compatibility)
    signal input h_file_lo;
    signal input h_file_hi;
    signal input salt;
    signal input meta;
    
    // Output: leaf commitment
    signal output leaf;
    
    // Poseidon hash for leaf commitment: Poseidon(h_file, salt, meta)
    component poseidon = Poseidon(4);
    poseidon.inputs[0] <== h_file_lo;
    poseidon.inputs[1] <== h_file_hi;
    poseidon.inputs[2] <== salt;
    poseidon.inputs[3] <== meta;
    
    leaf <== poseidon.out;
}

// Merkle proof verification circuit
template MerkleProofVerifier(depth) {
    // Public inputs
    signal input merkleRoot;
    // Public metadata commitment (e.g., keccak(fileName) or other agreed commitment)
    signal input metaPublic;
    
    // Private inputs (in templates all inputs are private by default in circom v2)
    signal input h_file_lo;
    signal input h_file_hi;
    signal input salt;
    signal input meta;
    signal input pathElements[depth];
    signal input pathIndices[depth];
    
    // Output
    signal output verified;
    
    // Step 1: Compute leaf commitment
    component fileCommitment = FileCommitment();
    fileCommitment.h_file_lo <== h_file_lo;
    fileCommitment.h_file_hi <== h_file_hi;
    fileCommitment.salt <== salt;
    fileCommitment.meta <== meta;
    
    // Step 2: Constrain public metadata equals the private meta used in leaf
    component eqMeta = IsEqual();
    eqMeta.in[0] <== meta;
    eqMeta.in[1] <== metaPublic;
    // eqMeta.out must be 1
    component isMetaValid = IsZero();
    isMetaValid.in <== 1 - eqMeta.out;
    // Step 3: Walk Merkle path using Poseidon hash
    signal currentHash;
    currentHash <== fileCommitment.leaf;
    
    // Poseidon hash component for tree nodes
    component poseidon = Poseidon(2);
    
    // Walk up the Merkle tree
    for (var i = 0; i < depth; i++) {
        // Create input for Poseidon hash based on path index
        poseidon.inputs[0] <== pathIndices[i] == 0 ? currentHash : pathElements[i];
        poseidon.inputs[1] <== pathIndices[i] == 0 ? pathElements[i] : currentHash;
        
        // Update current hash
        currentHash <== poseidon.out;
    }
    
    // Step 4: Check if the computed root matches the input root
    component eq = IsEqual();
    eq.in[0] <== currentHash;
    eq.in[1] <== merkleRoot;
    
    verified <== eq.out;
}

// Equality check
template IsEqual() {
    signal input in[2];
    signal output out;
    
    component eq = IsZero();
    eq.in <== in[0] - in[1];
    out <== 1 - eq.out;
}

// Zero check
template IsZero() {
    signal input in;
    signal output out;
    
    signal inv;
    inv <== in != 0 ? 1 / in : 0;
    out <== 1 - (in * inv);
}

// Main component - 3 levels deep Merkle tree
component main = MerkleProofVerifier(3);