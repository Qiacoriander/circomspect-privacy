pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

// Circuit to prove knowledge of a preimage to a Poseidon hash
// Public inputs: hash (the Poseidon hash output)
// Private inputs: preimage (the secret value that hashes to the given hash)
template HashPreimage() {
    // Private input - the secret preimage
    signal input preimage;
    
    // Public input - the expected hash value
    signal input hash;
    
    // Output signal (not used but required for circuit structure)
    signal output valid;
    
    // Create Poseidon hash component with 1 input
    component poseidon = Poseidon(1);
    
    // Connect the preimage to the Poseidon hasher
    poseidon.inputs[0] <== preimage;
    
    // Constraint: the computed hash must equal the public hash input
    poseidon.out === hash;
    
    // Set output to 1 to indicate the proof is valid
    valid <== 1;
}

// Main component - this is what gets compiled
// The hash input should be public so the verifier knows what hash is being proven
component main{public [hash]} = HashPreimage();
