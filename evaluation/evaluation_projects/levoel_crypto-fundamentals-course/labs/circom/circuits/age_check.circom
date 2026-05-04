pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";

// AgeCheck: Capstone ZK circuit for age verification
// Proves: "My age >= threshold" without revealing exact age.
//
// Real-world use case: KYC/identity verification
//   - Venue: "Prove you are >= 18" (threshold = 18)
//   - User proves age >= 18 without revealing exact birthday
//   - Verifier learns only: YES (age >= 18) or NO
//
// Constraints: ~200 (GreaterEqThan comparator)
// Usage:
//   Input:  { "age": "25", "threshold": "18" }
//
// Uses circomlib GreaterEqThan with 8-bit width (ages 0-255).

template AgeCheck(n) {
    // Private input: the actual age (not revealed)
    signal input age;

    // Public input: the minimum age threshold
    signal input threshold;

    // Output: 1 if age >= threshold, 0 otherwise
    // (constraint enforces it must be 1)
    signal output isOldEnough;

    // Check: age >= threshold using circomlib comparator
    component geq = GreaterEqThan(n);
    geq.in[0] <== age;
    geq.in[1] <== threshold;

    // Constrain output to be 1 (proof is valid only if age >= threshold)
    isOldEnough <== geq.out;
    isOldEnough === 1;
}

// n=8 bits: supports ages 0-255 (sufficient for human ages)
component main { public [threshold] } = AgeCheck(8);
