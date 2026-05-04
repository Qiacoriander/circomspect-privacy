pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";

/**
 * TransportProof
 * Proves that commute minutes have been reduced without revealing
 * the exact minutes.
 */
template TransportProof() {
    signal input previousCommuteMinutes;
    signal input currentCommuteMinutes;
    signal input minReductionMinutes;

    signal output isValid;

    signal diff;
    diff <== previousCommuteMinutes - currentCommuteMinutes;

    signal diffMinusMin;
    diffMinusMin <== diff - minReductionMinutes;

    component cmp = IsPositive();
    cmp.in <== diffMinusMin;

    isValid <== cmp.out;
}

template IsPositive() {
    signal input in;
    signal output out;

    out * (1 - out) === 0;
    in  * (1 - out) === 0;
}

component main = TransportProof();
