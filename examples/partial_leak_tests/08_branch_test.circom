pragma circom 2.0.0;

// Test case: Privacy leakage in branch contexts
// Purpose: Test how privacy taint analysis handles conditional branches
// Expected: Different taint propagation in different scenarios

template SimpleBranch() {
    signal input secret;
    signal output result;
    
    var temp;
    if (secret < 100) {
        temp = secret & 0xFF;  // Branch depends on secret
    } else {
        temp = secret >> 2;
    }
    result <== temp;
}

template PublicCondition() {
    signal input public_val;
    signal input secret;
    signal output result;
    
    var temp;
    if (public_val < 50) {  // Branch depends on public value
        temp = secret & 1;     // Only extract 1 bit
    } else {
        temp = secret & 3;     // Extract 2 bits
    }
    result <== temp;
}

template NestedBranch() {
    signal input secret;
    signal output result;
    
    var temp = 0;
    if (secret < 128) {
        if (secret < 64) {
            temp = secret & 1;
        } else {
            temp = secret & 3;
        }
    } else {
        temp = secret >> 4;
    }
    result <== temp;
}

template BranchWithLeakage() {
    signal input secret;
    signal output is_small;
    signal output value;
    
    // Branch condition itself is a leakage (1 bit)
    is_small <== (secret < 100) ? 1 : 0;
    
    // Value in branch
    var temp;
    if (secret < 100) {
        temp = secret;
    } else {
        temp = secret * 2;
    }
    value <== temp;
}

component main = SimpleBranch();
