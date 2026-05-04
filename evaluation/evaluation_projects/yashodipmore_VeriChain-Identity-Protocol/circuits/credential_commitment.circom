pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/**
 * VeriChain Credential Commitment Circuit
 * 
 * This circuit allows a user to prove they have a valid credential
 * without revealing the actual credential data.
 * 
 * Public Inputs:
 * - commitment: The Poseidon hash of (secret, nullifier, credentialType)
 * - credentialType: The type of credential being proven
 * 
 * Private Inputs:
 * - secret: User's secret value
 * - nullifier: Unique identifier to prevent double-spending
 * - credentialValue: The actual credential value
 * - credentialHash: Hash of the credential data
 */
template CredentialCommitment() {
    // Public inputs
    signal input commitment;
    signal input credentialType;
    
    // Private inputs
    signal input secret;
    signal input nullifier;
    signal input credentialValue;
    signal input credentialHash;
    
    // Output
    signal output nullifierHash;
    signal output valid;
    
    // Calculate commitment from private inputs
    component poseidon = Poseidon(3);
    poseidon.inputs[0] <== secret;
    poseidon.inputs[1] <== nullifier;
    poseidon.inputs[2] <== credentialType;
    
    // Verify commitment matches
    commitment === poseidon.out;
    
    // Calculate nullifier hash (for preventing double-use)
    component nullifierHasher = Poseidon(2);
    nullifierHasher.inputs[0] <== nullifier;
    nullifierHasher.inputs[1] <== secret;
    nullifierHash <== nullifierHasher.out;
    
    // Verify credential hash is non-zero (credential exists)
    component isZero = IsZero();
    isZero.in <== credentialHash;
    
    // valid = 1 if credentialHash is NOT zero
    valid <== 1 - isZero.out;
}

component main {public [commitment, credentialType]} = CredentialCommitment();
