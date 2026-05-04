pragma circom 2.0.0;

// Multiplier2: Hello World ZK circuit
// Proves: "I know a and b such that a * b = c"
// without revealing a or b.
//
// Constraints: 1 (single quadratic constraint)
// Usage:
//   Input:  { "a": "3", "b": "11" }
//   Output: c = 33

template Multiplier2() {
    // Input signals (private by default)
    signal input a;
    signal input b;

    // Output signal (public)
    signal output c;

    // Constraint: c must equal a * b
    // <== does BOTH assignment AND constraint (SAFE)
    c <== a * b;
}

component main = Multiplier2();
