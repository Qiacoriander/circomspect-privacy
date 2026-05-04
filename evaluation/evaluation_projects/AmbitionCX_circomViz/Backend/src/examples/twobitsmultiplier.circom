pragma circom 2.0.0;

template TwoBitMultiplier() {
    signal input a0;  // LSB of first number
    signal input a1;  // MSB of first number
    signal input b0;  // LSB of second number
    signal input b1;  // MSB of second number
    signal output out;

    // Multiplicative constraints (4)
    signal p0 <== a0 * b0;  // Constraint 1: a0×b0
    signal p1 <== a0 * b1;  // Constraint 2: a0×b1
    signal p2 <== a1 * b0;  // Constraint 3: a1×b0
    signal p3 <== a1 * b1;  // Constraint 4: a1×b1

    // Linear constraints (4)
    signal s1 <== p1 + p2;  // Constraint 5: p1+p2
    signal s2 <== s1 * 2;   // Constraint 6: s1×2 (linear scaling)
    signal s3 <== p3 * 4;   // Constraint 7: p3×4 (linear scaling)
    out <== p0 + s2 + s3;   // Constraint 8: Final sum
}

component main = TwoBitMultiplier();