pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/poseidon.circom";

template AgeVerification() {
    // Private inputs
    signal input birthYear;
    signal input birthMonth;
    signal input birthDay;
    signal input salt;
    
    // Public inputs
    signal input currentYear;
    signal input currentMonth;
    signal input currentDay;
    signal input minAge;
    
    // Output
    signal output valid;
    signal output commitment;
    
    // Calculate age in years (simplified)
    signal ageYears;
    ageYears <== currentYear - birthYear;
    
    // Check age >= minAge
    component ageCheck = GreaterEqThan(8);
    ageCheck.in[0] <== ageYears;
    ageCheck.in[1] <== minAge;
    
    valid <== ageCheck.out;
    
    // Generate commitment (Poseidon hash of private data + salt)
    component hasher = Poseidon(4);
    hasher.inputs[0] <== birthYear;
    hasher.inputs[1] <== birthMonth;
    hasher.inputs[2] <== birthDay;
    hasher.inputs[3] <== salt;
    
    commitment <== hasher.out;
}

component main {public [currentYear, currentMonth, currentDay, minAge]} = AgeVerification();
