pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

/**
 * Simple Hash Verifier Circuit
 * 
 * Proves knowledge of a preimage without revealing it.
 * This is a simpler circuit for initial testing.
 * 
 * Private: preimage (the secret)
 * Public: hash (the commitment)
 */

template HashVerifier() {
    signal input preimage;      // Private - the secret value
    signal input expectedHash;  // Public - the expected hash
    
    signal output isValid;      // 1 if preimage hashes to expectedHash
    
    component hasher = Poseidon(1);
    hasher.inputs[0] <== preimage;
    
    component isEqual = IsEqual();
    isEqual.in[0] <== hasher.out;
    isEqual.in[1] <== expectedHash;
    
    isValid <== isEqual.out;
}

component main {public [expectedHash]} = HashVerifier();
