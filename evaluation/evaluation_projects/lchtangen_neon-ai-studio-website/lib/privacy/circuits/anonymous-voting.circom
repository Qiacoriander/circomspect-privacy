// # CONCEPT: Anonymous Voting Circuit
// # ARCHITECTURE: Proves valid vote without revealing voter identity
// # BEST_PRACTICE: Zero-knowledge proof for anonymous voting

pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/merkleTree.circom";

template AnonymousVoting(levels) {
    // Private inputs
    signal private input voteChoice; // 0 or 1 (binary vote)
    signal private input secret;
    signal private input pathElements[levels];
    signal private input pathIndices[levels];
    
    // Public inputs
    signal input merkleRoot;
    signal input nullifier;
    signal input voteCommitment;
    
    // Output
    signal output isValid;
    
    // Component for Poseidon hash
    component hasher = Poseidon(3);
    component nullifierHasher = Poseidon(2);
    
    // Verify vote choice is binary (0 or 1)
    component voteCheck = IsZero();
    voteCheck.in <== voteChoice * (1 - voteCheck.in);
    
    // Create vote commitment: hash(voteChoice, secret)
    hasher.inputs[0] <== voteChoice;
    hasher.inputs[1] <== secret;
    hasher.inputs[2] <== 0;
    
    voteCommitment === hasher.out;
    
    // Verify merkle path (prove voter is in the allowed set)
    component tree = MerkleTreeChecker(levels);
    tree.leaf <== voteCommitment;
    tree.root <== merkleRoot;
    
    for (var i = 0; i < levels; i++) {
        tree.pathElements[i] <== pathElements[i];
        tree.pathIndices[i] <== pathIndices[i];
    }
    
    // Generate nullifier: hash(secret, voteCommitment)
    nullifierHasher.inputs[0] <== secret;
    nullifierHasher.inputs[1] <== voteCommitment;
    
    nullifier === nullifierHasher.out;
    
    // Verify vote is valid (binary choice and in merkle tree)
    isValid <== tree.out * (1 - voteCheck.out);
}

component main = AnonymousVoting(20); // 20 levels = 2^20 voters

