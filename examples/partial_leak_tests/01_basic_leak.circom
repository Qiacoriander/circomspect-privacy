pragma circom 2.0.0;

// Test case: Basic information leakage through bit operations
// Expected: PartialLeak taint level, but below threshold (no quantified report)
template BasicLeak() {
    signal private input secret;
    signal output bit_out;
    signal output comparison_out;
    
    // Bit extraction: leaks 1 bit (lowest bit)
    bit_out <== secret & 1;
    
    // Comparison: leaks 1 bit (whether secret < 100)
    // Using LessThan component from circomlib
    component lt = LessThan(8);  // 8-bit comparison
    lt.in[0] <== secret;
    lt.in[1] <== 100;
    comparison_out <== lt.out;
    
    // Total leakage: 2 bits (1 from bit extract, 1 from comparison)
    // Threshold T(x) = min(8, max(1, 0.125*254)) = 8
    // L(x) = 2 < T(x) = 8, so no quantified leakage report
}

// LessThan component (simplified version for testing)
template LessThan(n) {
    signal input in[2];
    signal output out;
    
    // Simplified: just check if in[0] < in[1]
    // In real circomlib, this uses Num2Bits
    signal diff;
    diff <== in[1] - in[0];
    out <== diff;  // Simplified for testing
}

component main = BasicLeak();
