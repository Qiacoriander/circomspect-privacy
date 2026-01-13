pragma circom 2.0.0;

// Leaks bit 0
function leakBit0(x) {
    return x & 1;
}

// Leaks bit 1
function leakBit1(x) {
    return (x >> 1) & 1;
}

// Calls two other functions
function leakTwoBits(x) {
    // Should accumulate to 2 bits
    return leakBit0(x) + leakBit1(x);
}

template Main() {
    signal input in1;
    signal input in2;
    signal input in3;
    
    signal output out1;
    signal output out2;
    signal output out3;

    // Case 1: Nested calls aggregation
    // leakTwoBits -> leakBit0 + leakBit1
    // Expected: in1 leaks 2 bits (Bit 0 and Bit 1)
    out1 <== leakTwoBits(in1);

    // Case 2: Direct multiple calls to different functions
    // Expected: in2 leaks 2 bits
    out2 <== leakBit0(in2) + leakBit1(in2);

    // Case 3: Duplicate calls to same function
    // leakBit0 leaks Bit 0. Calling it twice leaks the SAME Bit 0.
    // Expected: in3 leaks 1 bit (Deduplicated)
    out3 <== leakBit0(in3) + leakBit0(in3);
}

component main = Main();
