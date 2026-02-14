template TestMaskShift() {
    signal input in;
    signal output out;

    var sum = 0;
    for (var i = 0; i < 8; i++) {
        // Pattern: (in & (1 << i))
        // This extracts the i-th bit (weighted).
        // Should be recognized as 1-bit leakage per iteration.
        sum += (in & (1 << i)); 
    }
    out <== sum;
}

component main = TestMaskShift();
