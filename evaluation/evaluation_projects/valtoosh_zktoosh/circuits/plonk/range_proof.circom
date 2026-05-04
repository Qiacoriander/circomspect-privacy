pragma circom 2.1.8;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/*
 * Phase 6D: Range Proof
 * Proves that a value is within a specified range without revealing the exact value
 * This prevents gas-based inference attacks and ensures constant-time proof generation
 */

/**
 * Basic Range Proof
 * Proves that 0 <= value <= maxValue
 * @param numBits - Number of bits for range (64 bits = up to 2^64 - 1)
 */
template RangeProof(numBits) {
    signal input value;          // Secret value to prove range for
    signal input maxValue;       // Maximum allowed value (public)

    signal output isValid;       // 1 if value is in range

    // Decompose value into bits (ensures value < 2^numBits)
    component valueBits = Num2Bits(numBits);
    valueBits.in <== value;

    // Check that value <= maxValue
    component leCheck = LessEqThan(numBits);
    leCheck.in[0] <== value;
    leCheck.in[1] <== maxValue;

    // Also check value >= 0 (implicit in unsigned, but explicit for clarity)
    component geCheck = GreaterEqThan(numBits);
    geCheck.in[0] <== value;
    geCheck.in[1] <== 0;

    // Combine checks
    signal intermediate;
    intermediate <== leCheck.out * geCheck.out;
    isValid <== intermediate;
}

/**
 * Strict Range Proof with Bit Validation
 * More secure version that validates every bit
 */
template StrictRangeProof(numBits) {
    signal input value;
    signal input minValue;
    signal input maxValue;

    signal output isValid;

    // Decompose value into bits
    component valueBits = Num2Bits(numBits);
    valueBits.in <== value;

    // Verify bit decomposition is correct (sum of bits equals value)
    component bitsToNum = Bits2Num(numBits);
    for (var i = 0; i < numBits; i++) {
        bitsToNum.in[i] <== valueBits.out[i];
    }
    bitsToNum.out === value;

    // Check value >= minValue
    component geMin = GreaterEqThan(numBits);
    geMin.in[0] <== value;
    geMin.in[1] <== minValue;

    // Check value <= maxValue
    component leMax = LessEqThan(numBits);
    leMax.in[0] <== value;
    leMax.in[1] <== maxValue;

    // Combine all checks
    signal intermediate;
    intermediate <== geMin.out * leMax.out;
    isValid <== intermediate;
}

/**
 * Multi-Value Range Proof
 * Proves that multiple values are all within range
 * Useful for proving multiple constraints at once
 */
template MultiRangeProof(numValues, numBits) {
    signal input values[numValues];
    signal input maxValue;

    signal output isValid;

    component rangeProofs[numValues];
    signal intermediate[numValues];

    // Check each value
    for (var i = 0; i < numValues; i++) {
        rangeProofs[i] = RangeProof(numBits);
        rangeProofs[i].value <== values[i];
        rangeProofs[i].maxValue <== maxValue;

        if (i == 0) {
            intermediate[i] <== rangeProofs[i].isValid;
        } else {
            intermediate[i] <== intermediate[i - 1] * rangeProofs[i].isValid;
        }
    }

    isValid <== intermediate[numValues - 1];
}
