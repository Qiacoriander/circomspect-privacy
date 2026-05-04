pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";

// RangeProof: Proves a value is within [min, max] range
// Proves: "min <= value <= max" without revealing value.
//
// Constraints: ~200 (two comparator circuits)
// Usage:
//   Input:  { "value": "42", "min": "18", "max": "100" }
//
// Uses circomlib GreaterEqThan and LessEqThan comparators.
// Bit width 64 supports values up to 2^64 - 1.

template RangeProof(n) {
    // Private input: the secret value
    signal input value;

    // Public inputs: range bounds
    signal input min;
    signal input max;

    // Check: value >= min
    component geq = GreaterEqThan(n);
    geq.in[0] <== value;
    geq.in[1] <== min;
    geq.out === 1;

    // Check: value <= max
    component leq = LessEqThan(n);
    leq.in[0] <== value;
    leq.in[1] <== max;
    leq.out === 1;
}

// n=64 bits: supports values up to 2^64 - 1
component main { public [min, max] } = RangeProof(64);
