pragma circom 2.0.0;

include "../utilities.circom";
include "circomlib/circuits/poseidon.circom";

/*
 * Range Proof Circuit - Library Version
 * 
 * Proves that a private value is within a specified range [min, max]
 * without revealing the actual value
 * Used for LOC counts, commit counts, collaboration percentages, etc.
 * 
 * Library version - no main component for use in other circuits
 */

template RangeProof() {
    // Public inputs
    signal input min;
    signal input max;
    signal input commitment; // Hash of the secret value
    
    // Private inputs
    signal input value;
    signal input nonce;
    
    // Outputs
    signal output valid;
    
    // Verify the commitment
    component hasher = Poseidon(2);
    hasher.inputs[0] <== value;
    hasher.inputs[1] <== nonce;
    
    component commitmentCheck = IsEqual();
    commitmentCheck.in[0] <== hasher.out;
    commitmentCheck.in[1] <== commitment;
    
    // Check that min <= value <= max
    component minCheck = GreaterEqThan(64);
    minCheck.in[0] <== value;
    minCheck.in[1] <== min;
    
    component maxCheck = LessEqThan(64);
    maxCheck.in[0] <== value;
    maxCheck.in[1] <== max;
    
    // All checks must pass
    component andGate1 = AND();
    andGate1.a <== commitmentCheck.out;
    andGate1.b <== minCheck.out;
    
    component andGate2 = AND();
    andGate2.a <== andGate1.out;
    andGate2.b <== maxCheck.out;
    
    valid <== andGate2.out;
}

/*
 * Range Proof with Custom Bit Length
 */
template RangeProofCustom(n) {
    signal input min;
    signal input max;
    signal input value;
    signal output valid;
    
    // Check bounds
    component minCheck = GreaterEqThan(n);
    minCheck.in[0] <== value;
    minCheck.in[1] <== min;
    
    component maxCheck = LessEqThan(n);
    maxCheck.in[0] <== value;
    maxCheck.in[1] <== max;
    
    component andGate = AND();
    andGate.a <== minCheck.out;
    andGate.b <== maxCheck.out;
    
    valid <== andGate.out;
}

// No main component - this is a library circuit 