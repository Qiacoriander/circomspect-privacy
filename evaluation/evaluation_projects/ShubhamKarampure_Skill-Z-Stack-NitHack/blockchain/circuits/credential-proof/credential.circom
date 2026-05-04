pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

/**
 * @title CredentialProof
 * @dev Prove possession of a valid credential without revealing its details
 * Uses Poseidon hash for efficient zk-friendly hashing
 */
template CredentialProof() {
    // Private inputs (credential details - hidden)
    signal input credentialId;
    signal input holderAddress;
    signal input issuerAddress;
    signal input credentialType;
    signal input issueDate;
    signal input expirationDate;
    
    // Public inputs
    signal input currentTimestamp;
    signal input credentialHash; // Expected hash to verify against
    
    // Outputs
    signal output isValid;
    signal output isNotExpired;
    
    // Hash the credential data using Poseidon (zk-friendly hash)
    component hasher = Poseidon(6);
    hasher.inputs[0] <== credentialId;
    hasher.inputs[1] <== holderAddress;
    hasher.inputs[2] <== issuerAddress;
    hasher.inputs[3] <== credentialType;
    hasher.inputs[4] <== issueDate;
    hasher.inputs[5] <== expirationDate;
    
    // Verify computed hash matches expected hash
    signal hashMatch;
    hashMatch <== hasher.out - credentialHash;
    hashMatch === 0;
    
    // Check if credential is not expired (or never expires)
    // If expirationDate == 0, it never expires
    signal isNeverExpires;
    component isZero = IsZero();
    isZero.in <== expirationDate;
    isNeverExpires <== isZero.out;
    
    // Check if current time is less than expiration
    component notExpiredYet = LessThan(64);
    notExpiredYet.in[0] <== currentTimestamp;
    notExpiredYet.in[1] <== expirationDate;
    
    // Credential is not expired if: never expires OR current < expiration
    isNotExpired <== isNeverExpires + notExpiredYet.out - (isNeverExpires * notExpiredYet.out);
    
    // Credential is valid if hash matches AND not expired
    isValid <== isNotExpired;
    
    // Ensure outputs are binary
    isValid * (1 - isValid) === 0;
    isNotExpired * (1 - isNotExpired) === 0;
}

component main {public [currentTimestamp, credentialHash]} = CredentialProof();
