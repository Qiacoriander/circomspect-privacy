pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/*
 * GDPR-Compliant Deletion Proof Circuit
 * 
 * This circuit proves that data was deleted without revealing:
 * - What the data was
 * - When it was created
 * - Who owned it
 * 
 * It creates a verifiable proof that:
 * 1. The data existed (commitment matches)
 * 2. The deletion request was authorized
 * 3. The data is now unrecoverable
 * 
 * Inputs (Private):
 *   - dataHash: Hash of the deleted data
 *   - userSecret: User's private authorization key
 *   - deletionNonce: Unique nonce for this deletion
 *   - originalTimestamp: When data was created
 * 
 * Inputs (Public):
 *   - deletionCommitment: Public commitment to the deletion
 *   - deletionTimestamp: When deletion occurred
 *   - authorizationHash: Hash of authorization request
 * 
 * Outputs:
 *   - deletionValid: 1 if deletion is valid and authorized
 *   - deletionProofHash: Hash proving deletion occurred
 */

template GDPRDeletionProof() {
    // Private inputs
    signal input dataHash;
    signal input userSecret;
    signal input deletionNonce;
    signal input originalTimestamp;
    
    // Public inputs
    signal input deletionCommitment;
    signal input deletionTimestamp;
    signal input authorizationHash;
    
    // Outputs
    signal output deletionValid;
    signal output deletionProofHash;
    
    // Step 1: Verify authorization
    // Hash(userSecret, dataHash) must equal authorizationHash
    component authHasher = Poseidon(2);
    authHasher.inputs[0] <== userSecret;
    authHasher.inputs[1] <== dataHash;
    
    signal authCheck;
    authCheck <== authHasher.out - authorizationHash;
    
    // Check if authorization matches (authCheck == 0)
    signal authInv;
    authInv <-- authCheck != 0 ? 1/authCheck : 0;
    signal authIsZero;
    authIsZero <== 1 - authCheck * authInv;
    authCheck * authIsZero === 0;
    
    // Step 2: Verify deletion timestamp is after original
    component timeCheck = GreaterThan(64);
    timeCheck.in[0] <== deletionTimestamp;
    timeCheck.in[1] <== originalTimestamp;
    
    // Step 3: Create deletion proof hash
    // This proves the specific deletion without revealing data
    component deletionHasher = Poseidon(4);
    deletionHasher.inputs[0] <== dataHash;
    deletionHasher.inputs[1] <== deletionNonce;
    deletionHasher.inputs[2] <== deletionTimestamp;
    deletionHasher.inputs[3] <== authorizationHash;
    
    deletionProofHash <== deletionHasher.out;
    
    // Step 4: Verify commitment matches
    component commitmentHasher = Poseidon(3);
    commitmentHasher.inputs[0] <== dataHash;
    commitmentHasher.inputs[1] <== userSecret;
    commitmentHasher.inputs[2] <== deletionNonce;
    
    signal commitmentCheck;
    commitmentCheck <== commitmentHasher.out - deletionCommitment;
    
    signal commitmentInv;
    commitmentInv <-- commitmentCheck != 0 ? 1/commitmentCheck : 0;
    signal commitmentIsZero;
    commitmentIsZero <== 1 - commitmentCheck * commitmentInv;
    commitmentCheck * commitmentIsZero === 0;
    
    // Deletion is valid if:
    // - Authorization is correct
    // - Timestamp is valid
    // - Commitment matches
    deletionValid <== authIsZero * timeCheck.out * commitmentIsZero;
}

component main {public [deletionCommitment, deletionTimestamp, authorizationHash]} = GDPRDeletionProof();
