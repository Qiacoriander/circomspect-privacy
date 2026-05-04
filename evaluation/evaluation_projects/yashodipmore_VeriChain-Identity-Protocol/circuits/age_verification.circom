pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/**
 * VeriChain Age Verification Circuit
 * 
 * This circuit allows a user to prove they are above a certain age
 * without revealing their actual birthdate.
 * 
 * Public Inputs:
 * - currentTimestamp: Current Unix timestamp
 * - minAge: Minimum required age in years
 * - commitment: Hash of (birthTimestamp, secret)
 * 
 * Private Inputs:
 * - birthTimestamp: User's birth date as Unix timestamp
 * - secret: User's secret for commitment
 */
template AgeVerification() {
    // Public inputs
    signal input currentTimestamp;
    signal input minAge;
    signal input commitment;
    
    // Private inputs
    signal input birthTimestamp;
    signal input secret;
    
    // Output
    signal output isAboveAge;
    
    // Constants
    var SECONDS_PER_YEAR = 31536000; // 365 days
    
    // Verify commitment
    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== birthTimestamp;
    poseidon.inputs[1] <== secret;
    commitment === poseidon.out;
    
    // Calculate age in seconds
    signal ageInSeconds;
    ageInSeconds <== currentTimestamp - birthTimestamp;
    
    // Calculate minimum age in seconds
    signal minAgeInSeconds;
    minAgeInSeconds <== minAge * SECONDS_PER_YEAR;
    
    // Compare: ageInSeconds >= minAgeInSeconds
    component gte = GreaterEqThan(64);
    gte.in[0] <== ageInSeconds;
    gte.in[1] <== minAgeInSeconds;
    
    isAboveAge <== gte.out;
    
    // Ensure the result is 1 (above age)
    isAboveAge === 1;
}

component main {public [currentTimestamp, minAge, commitment]} = AgeVerification();
