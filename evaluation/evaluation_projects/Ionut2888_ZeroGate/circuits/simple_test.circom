pragma circom 2.0.0;

// Simple test circuit to verify our setup works
// This circuit just checks that we know a secret value
template SimpleTest() {
    // Private input - the secret
    signal input secret;
    
    // Public input - a constraint value
    signal input expectedValue;
    
    // Output signal
    signal output valid;
    
    // Simple constraint: secret must equal expectedValue
    secret === expectedValue;
    
    // Set output to 1 to indicate the proof is valid
    valid <== 1;
}

// Main component
component main = SimpleTest();
