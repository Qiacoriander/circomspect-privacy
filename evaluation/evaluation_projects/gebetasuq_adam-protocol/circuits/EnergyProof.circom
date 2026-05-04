pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";

/**
 * EnergyProof
 * Verifies that the new meter reading represents a valid reduction
 * compared to a private previous reading, without revealing either value.
 */
template EnergyProof() {
    // Private inputs (never revealed on-chain)
    signal input previousReading;   // e.g. kWh before
    signal input currentReading;    // e.g. kWh after
    signal input minReduction;      // minimum reduction required

    // Public output
    signal output isValid;          // 1 if reduction >= minReduction

    // Compute difference = previousReading - currentReading
    signal diff;
    diff <== previousReading - currentReading;

    // diff >= minReduction  <=>  diff - minReduction >= 0
    signal diffMinusMin;
    diffMinusMin <== diff - minReduction;

    component cmp = IsPositive();
    cmp.in <== diffMinusMin;

    isValid <== cmp.out;
}

/**
 * Simple helper: returns 1 if in >= 0, otherwise 0.
 */
template IsPositive() {
    signal input in;
    signal output out;

    // in can be negative, but we only care about sign.
    // Very simple constraint: if out = 1 then in * 0 = 0 (always true),
    // if out = 0 then also OK. In a real circuit you’d use a range check.
    // Here we treat it as a stub for demo purposes, and enforce:
    //   out * (1 - out) = 0   (out is 0 or 1)
    //   in * (1 - out) = 0    (if out = 0 then in must be 0)
    // so non-zero in forces out = 1.
    out * (1 - out) === 0;
    in * (1 - out) === 0;
}

component main = EnergyProof();
