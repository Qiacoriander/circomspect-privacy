pragma circom 2.0.0;

// Test case: Shift operation leakage
// Expected: PartialLeak taint, moderate leakage (4 bits from shift)
template ShiftLeak() {
    signal input secret;
    signal output shifted_out;
    signal output bit_out;
    
    // Right shift by 4: exposes some bits
    shifted_out <-- secret >> 4;
    
    // Additional bit extraction: 1 bit
    bit_out <-- secret & 1;
    
    // Total leakage: 4 (shift) + 1 (bit extract) = 5 bits
    // Still below T(x) = 8
}

component main = ShiftLeak();
