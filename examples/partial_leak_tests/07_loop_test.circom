pragma circom 2.0.0;

// Test case: Privacy leakage in loop contexts
// Purpose: Test how privacy taint analysis handles loops
// Expected: Taint propagation through loop iterations

template LoopBitExtractor() {
    signal input secret;
    signal output bits[8];
    
    // Extract 8 bits in a loop
    var temp = secret;
    for (var i = 0; i < 8; i++) {
        bits[i] <== temp & 1;
        temp = temp >> 1;
    }
}

template LoopAccumulator() {
    signal input values[4];
    signal output result;
    
    // Accumulate values in a loop
    var sum = 0;
    for (var i = 0; i < 4; i++) {
        sum = sum + values[i];
    }
    result <== sum;
}

template ConditionalLoop() {
    signal input data;
    signal output processed;
    
    // Process data with conditional loop
    var temp = data;
    for (var i = 0; i < 4; i++) {
        if (i < 2) {
            temp = temp & 0xFF;  // Mask to 8 bits
        } else {
            temp = temp >> 2;     // Shift right
        }
    }
    processed <== temp;
}

component main = LoopBitExtractor();
