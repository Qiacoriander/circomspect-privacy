pragma circom 2.1.4;

// Correct path to the comparators library
include "node_modules/circomlib/circuits/comparators.circom";

template AadhaarIdentity() {
    // Private Inputs (Stay in browser)
    signal input aadhaarNumber;
    signal input age;
    
    // Public Signals (Verified by the blockchain)
    signal output isAdult;

    // FIX: Changed GreaterEqualThan to GreaterEqThan
    component gte = GreaterEqThan(32);
    gte.in[0] <== age;
    gte.in[1] <== 18;

    isAdult <== gte.out;
}

component main = AadhaarIdentity();