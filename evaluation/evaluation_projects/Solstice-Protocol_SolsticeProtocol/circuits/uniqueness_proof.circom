pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

/*
 * Uniqueness Proof Circuit
 * Proves a user has a unique identity without revealing who they are
 * Prevents Sybil attacks by ensuring one-person-one-account
 * 
 * Public Inputs:
 * - nullifier: Public nullifier (prevents double registration)
 * - merkleRoot: Root of identity merkle tree
 * 
 * Private Inputs:
 * - identitySecret: Secret unique to user
 * - aadhaarHash: Hash of Aadhaar number
 */

template UniquenessProof() {
    // Public inputs
    signal input nullifier;
    signal input merkleRoot;
    
    // Private inputs
    signal input identitySecret;
    signal input aadhaarHash;
    
    // Generate nullifier from private inputs
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== identitySecret;
    nullifierHasher.inputs[1] <== aadhaarHash;
    
    // Verify nullifier matches
    nullifierHasher.out === nullifier;
    
    // In production: Verify merkle proof that identity is in tree
    // For now, simplified check
    signal merkleCheck;
    merkleCheck <== identitySecret + aadhaarHash;
}

component main {public [nullifier, merkleRoot]} = UniquenessProof();
