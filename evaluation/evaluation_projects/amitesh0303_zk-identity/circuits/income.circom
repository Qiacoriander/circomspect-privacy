pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/poseidon.circom";

template IncomeVerification() {
    // Private inputs
    signal input annualIncome;  // In cents to avoid decimals
    signal input salt;
    
    // Public inputs
    signal input threshold;  // Minimum income threshold in cents
    
    // Outputs
    signal output valid;
    signal output commitment;
    
    // Check if income >= threshold
    component incomeCheck = GreaterEqThan(64);
    incomeCheck.in[0] <== annualIncome;
    incomeCheck.in[1] <== threshold;
    
    valid <== incomeCheck.out;
    
    // Generate commitment
    component hasher = Poseidon(2);
    hasher.inputs[0] <== annualIncome;
    hasher.inputs[1] <== salt;
    
    commitment <== hasher.out;
}

component main {public [threshold]} = IncomeVerification();
