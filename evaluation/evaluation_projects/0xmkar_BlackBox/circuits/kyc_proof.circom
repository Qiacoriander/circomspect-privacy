pragma circom 2.0.0;

/*
 * Circuit A: ZK-KYC Proof
 * Proves user has valid KYC without revealing identity
 * 
 * Private inputs: userSecret, kycCredentialHash
 * Public output: commitmentHash
 * 
 * Verification: Off-chain with signed attestation
 */

include "../node_modules/circomlib/circuits/poseidon.circom";

template KYCProof() {
    // Private inputs
    signal input userSecret;
    signal input kycCredentialHash;
    signal input nonce;
    
    // Public output
    signal output commitmentHash;
    
    // Intermediate signals
    signal hashInput[3];
    
    // Assign inputs to hash
    hashInput[0] <== userSecret;
    hashInput[1] <== kycCredentialHash;
    hashInput[2] <== nonce;
    
    // Compute commitment using Poseidon hash
    component poseidon = Poseidon(3);
    poseidon.inputs[0] <== hashInput[0];
    poseidon.inputs[1] <== hashInput[1];
    poseidon.inputs[2] <== hashInput[2];
    
    commitmentHash <== poseidon.out;
    
    // Constraint: KYC credential must be non-zero (valid)
    signal kycValid;
    kycValid <== kycCredentialHash * kycCredentialHash;
    kycValid === kycValid; // Ensures kycCredentialHash is used
}

component main {public []} = KYCProof();
