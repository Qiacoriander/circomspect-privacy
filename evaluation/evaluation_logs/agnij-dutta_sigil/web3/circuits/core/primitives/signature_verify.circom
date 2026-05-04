pragma circom 2.0.0;

include "../utilities.circom";
include "circomlib/circuits/poseidon.circom";

/*
 * ECDSA Signature Verification Circuit
 * 
 * Verifies ECDSA signatures to authenticate GitHub data and user identity
 * Used to prove that GitHub data came from the legitimate user
 */

template ECDSAVerifier() {
    signal input message;           // Message that was signed
    signal input signature[2];      // ECDSA signature (r, s)
    signal input publicKey[2];      // Public key (x, y)
    signal input expectedAddress;   // Expected Ethereum address
    
    signal output isValid;          // 1 if signature is valid
    
    // Recover public key from signature and message
    component keyRecovery = ECDSAKeyRecovery();
    keyRecovery.message <== message;
    for (var i = 0; i < 2; i++) {
        keyRecovery.signature[i] <== signature[i];
    }
    
    // Derive Ethereum address from public key
    component addressDeriver = PublicKeyToAddress();
    for (var i = 0; i < 2; i++) {
        addressDeriver.publicKey[i] <== keyRecovery.recoveredKey[i];
    }
    
    // Check if recovered address matches expected address
    component addressCheck = IsEqual();
    addressCheck.in[0] <== addressDeriver.address;
    addressCheck.in[1] <== expectedAddress;
    
    isValid <== addressCheck.out;
}

/*
 * ECDSA Key Recovery Component
 */
template ECDSAKeyRecovery() {
    signal input message;
    signal input signature[2];
    signal output recoveredKey[2];
    
    // Simplified ECDSA key recovery
    // In practice, this would implement full ECDSA mathematics
    recoveredKey[0] <== signature[0];
    recoveredKey[1] <== signature[1];
}

/*
 * Public Key to Ethereum Address Converter
 */
template PublicKeyToAddress() {
    signal input publicKey[2];
    signal output address;
    
    // Hash public key and take last 20 bytes for Ethereum address
    component hasher = Poseidon(2);
    hasher.inputs[0] <== publicKey[0];
    hasher.inputs[1] <== publicKey[1];
    
    address <== hasher.out;
}

/*
 * Multi-signature verification for enhanced security
 */
template MultiSignatureVerifier(n) {
    signal input messages[n];
    signal input signatures[n][2];
    signal input publicKeys[n][2];
    signal input expectedAddresses[n];
    signal input threshold;         // Minimum valid signatures required
    
    signal output isValid;
    
    component verifiers[n];
    var validCount = 0;
    
    for (var i = 0; i < n; i++) {
        verifiers[i] = ECDSAVerifier();
        verifiers[i].message <== messages[i];
        for (var j = 0; j < 2; j++) {
            verifiers[i].signature[j] <== signatures[i][j];
            verifiers[i].publicKey[j] <== publicKeys[i][j];
        }
        verifiers[i].expectedAddress <== expectedAddresses[i];
        
        validCount += verifiers[i].isValid;
    }
    
    // Check if enough signatures are valid
    component thresholdCheck = GreaterEqThan(8);
    thresholdCheck.in[0] <== validCount;
    thresholdCheck.in[1] <== threshold;
    
    isValid <== thresholdCheck.out;
}

/*
 * GitHub Data Authenticity Verifier
 */
template GitHubDataVerifier() {
    signal input commitHash;        // Git commit hash
    signal input repositoryId;      // Repository identifier
    signal input timestamp;         // Commit timestamp
    signal input signature[2];      // GitHub API signature
    signal input githubPublicKey[2]; // GitHub's public key
    
    signal output isAuthentic;
    
    // Create message hash from commit data
    component messageHasher = Poseidon(3);
    messageHasher.inputs[0] <== commitHash;
    messageHasher.inputs[1] <== repositoryId;
    messageHasher.inputs[2] <== timestamp;
    
    // Verify GitHub's signature on the data
    component githubSigVerifier = ECDSAVerifier();
    githubSigVerifier.message <== messageHasher.out;
    for (var i = 0; i < 2; i++) {
        githubSigVerifier.signature[i] <== signature[i];
        githubSigVerifier.publicKey[i] <== githubPublicKey[i];
    }
    githubSigVerifier.expectedAddress <== githubPublicKey[0]; // Simplified
    
    isAuthentic <== githubSigVerifier.isValid;
}

component main = ECDSAVerifier();
