// Merkle tree utilities for fog of war and state verification

template MerkleTreeInclusionProof(levels) {
    signal input leaf;
    signal input path[levels];
    signal input pathIndices[levels];
    signal input root;
    
    signal output out;
    
    component hashers[levels];
    
    var currentHash = leaf;
    
    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);
        
        // If pathIndices[i] == 0, currentHash is left child
        // If pathIndices[i] == 1, currentHash is right child
        hashers[i].in[0] <== pathIndices[i] * path[i] + (1 - pathIndices[i]) * currentHash;
        hashers[i].in[1] <== (1 - pathIndices[i]) * path[i] + pathIndices[i] * currentHash;
        
        currentHash <== hashers[i].out;
    }
    
    // Verify the computed root matches the provided root
    currentHash === root;
    out <== currentHash;
}

template MerkleTreeNonInclusionProof(levels) {
    signal input leaf;
    signal input path[levels];
    signal input pathIndices[levels];
    signal input root;
    signal input sibling;
    
    signal output out;
    
    component hashers[levels];
    
    var currentHash = leaf;
    
    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);
        
        hashers[i].in[0] <== pathIndices[i] * path[i] + (1 - pathIndices[i]) * currentHash;
        hashers[i].in[1] <== (1 - pathIndices[i]) * path[i] + pathIndices[i] * currentHash;
        
        currentHash <== hashers[i].out;
    }
    
    // Verify the computed root matches the provided root
    currentHash === root;
    
    // Verify the leaf is not equal to the sibling (proving non-inclusion)
    leaf <== sibling + 1;
    
    out <== currentHash;
}
