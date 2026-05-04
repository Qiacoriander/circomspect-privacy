pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";

/*
 * Search Inclusion Proof Circuit
 * 
 * This circuit proves that a search result is included in the search index
 * without revealing the content of the search query or other results.
 * 
 * This implements a Merkle tree inclusion proof for privacy-preserving search.
 * 
 * Public Inputs:
 * - root: Merkle root of the search index
 * - leaf_hash: Hash of the search result being proven
 * 
 * Private Inputs:
 * - path_elements: Sibling nodes along the Merkle path (depth levels)
 * - path_indices: Direction indicators (0 = left, 1 = right) for each level
 * - query_nullifier_secret: Secret for generating query nullifier
 */
template SearchInclusion(levels) {
    // Constraint: levels must be between 1 and 32
    assert(levels >= 1 && levels <= 32);
    
    // Public inputs
    signal input root;
    signal input leaf_hash;
    
    // Private inputs
    signal private input path_elements[levels];
    signal private input path_indices[levels];
    signal private input query_nullifier_secret;
    
    // Outputs
    signal output query_nullifier;
    signal output inclusion_proof;
    
    // Internal signals for Merkle path computation
    signal path_hash[levels + 1];
    
    // Component declarations
    component hashers[levels];
    component mux[levels];
    component nullifier_hasher = Poseidon(2);
    component proof_hasher = Poseidon(3);
    
    // Set the leaf as the starting point
    path_hash[0] <== leaf_hash;
    
    // Compute Merkle path from leaf to root
    for (var i = 0; i < levels; i++) {
        // Select the order of hashing based on path direction
        mux[i] = Mux1();
        mux[i].c[0] <== path_hash[i];
        mux[i].c[1] <== path_elements[i];
        mux[i].s <== path_indices[i];
        
        // Hash current node with sibling
        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out;
        hashers[i].inputs[1] <== path_elements[i];
        
        // Store hash for next level
        path_hash[i + 1] <== hashers[i].out;
    }
    
    // Verify that computed root matches the expected root
    component root_check = IsEqual();
    root_check.in[0] <== root;
    root_check.in[1] <== path_hash[levels];
    root_check.out === 1;
    
    // Generate query nullifier to prevent query replay attacks
    nullifier_hasher.inputs[0] <== leaf_hash;
    nullifier_hasher.inputs[1] <== query_nullifier_secret;
    query_nullifier <== nullifier_hasher.out;
    
    // Generate inclusion proof
    proof_hasher.inputs[0] <== root;
    proof_hasher.inputs[1] <== leaf_hash;
    proof_hasher.inputs[2] <== query_nullifier;
    inclusion_proof <== proof_hasher.out;
}

/*
 * Main component for search inclusion proof with 20 levels (supports ~1M entries)
 */
component main = SearchInclusion(20);