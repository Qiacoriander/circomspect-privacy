pragma circom 2.0.8;

include "../../delivery/ciminion_ks_poseidon.circom";
include "addition.circom";

// Main template that combines the addition verification with encryption
template top() {
    // Public inputs (master key)
    signal input MK_0;
    signal input MK_1;
    
    // Hash of the solution
    signal input H;
    
    // Private inputs (the solution)
    signal input a;
    signal input b;
    signal input claimed_sum;

    // Verify the addition
    component addition = AdditionVerifier();
    addition.a <== a;
    addition.b <== b;
    addition.claimed_sum <== claimed_sum;

    // Hash the solution
    // The Enc template expects pairs of values (nPairs*2 total values)
    // So we need at least 1 pair (2 values)
    component hash = Enc(1);
    hash.MK_0 <== MK_0;
    hash.MK_1 <== MK_1;
    hash.PT[0] <== a;
    hash.PT[1] <== b;
    
    // Note: We're only using the first pair of inputs
    // The claimed_sum is verified by the AdditionVerifier but not included in the hash

    // Verify the hash matches
    // H === hash.Out;
}

component main {public [MK_0, MK_1]} = top(); 