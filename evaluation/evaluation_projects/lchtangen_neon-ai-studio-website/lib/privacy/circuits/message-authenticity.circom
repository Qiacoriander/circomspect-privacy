// # CONCEPT: Encrypted Message Authenticity Circuit
// # ARCHITECTURE: Proves message authenticity without revealing content
// # BEST_PRACTICE: Zero-knowledge proof for encrypted message verification

pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/eddsa.circom";

template MessageAuthenticity() {
    // Private inputs
    signal private input messageHash;
    signal private input signatureR[2];
    signal private input signatureS;
    signal private input publicKeyA[2];
    
    // Public inputs
    signal input encryptedMessageHash;
    signal input publicKeyX[2];
    signal input timestamp;
    
    // Output
    signal output isValid;
    
    // Component for Poseidon hash
    component hasher = Poseidon(3);
    component messageHasher = Poseidon(2);
    
    // Verify message hash matches encrypted message hash
    messageHasher.inputs[0] <== messageHash;
    messageHasher.inputs[1] <== timestamp;
    
    encryptedMessageHash === messageHasher.out;
    
    // Verify EdDSA signature
    component verifier = EdDSAPoseidonVerifier();
    verifier.enabled <== 1;
    verifier.Ax <== publicKeyA[0];
    verifier.Ay <== publicKeyA[1];
    verifier.S <== signatureS;
    verifier.R8x <== signatureR[0];
    verifier.R8y <== signatureR[1];
    verifier.M <== messageHash;
    
    // Verify public key matches
    component pubKeyCheckX = IsEqual();
    component pubKeyCheckY = IsEqual();
    pubKeyCheckX.in[0] <== publicKeyA[0];
    pubKeyCheckX.in[1] <== publicKeyX[0];
    pubKeyCheckY.in[0] <== publicKeyA[1];
    pubKeyCheckY.in[1] <== publicKeyX[1];
    
    // Output is valid if signature is valid and public keys match
    isValid <== verifier.out * pubKeyCheckX.out * pubKeyCheckY.out;
}

component main = MessageAuthenticity();

