pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/poseidon.circom";

template CitizenshipVerification() {
    // Private inputs
    signal input countryCode;  // Encoded country code
    signal input documentNumber;
    signal input salt;
    
    // Public inputs
    signal input targetCountryCode;  // Country to verify membership
    
    // Outputs
    signal output valid;
    signal output commitment;
    
    // Check if citizen of target country
    component eq = IsEqual();
    eq.in[0] <== countryCode;
    eq.in[1] <== targetCountryCode;
    
    valid <== eq.out;
    
    // Generate commitment
    component hasher = Poseidon(3);
    hasher.inputs[0] <== countryCode;
    hasher.inputs[1] <== documentNumber;
    hasher.inputs[2] <== salt;
    
    commitment <== hasher.out;
}

component main {public [targetCountryCode]} = CitizenshipVerification();
