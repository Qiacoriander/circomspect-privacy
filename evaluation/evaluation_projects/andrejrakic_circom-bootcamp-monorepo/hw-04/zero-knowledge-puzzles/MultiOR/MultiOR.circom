pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/gates.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// Write a circuit that returns true when at least one
// element is 1. It should return false if all elements
// are 0. It should be unsatisfiable if any of the inputs
// are not 0 or not 1.

template MultiOR(n) {
    signal input in[n];
    signal output out;

    signal sums[n + 1];
    sums[0] <== 0;

    for (var i = 0; i < n; i++) {
        in[i] * (in[i] - 1) === 0;  // Enforce all inputs are either 0 or 1
        sums[i + 1] <== sums[i] + in[i];
    }

    component gt = GreaterThan(n);
    gt.in[0] <== sums[n];
    gt.in[1] <== 0;

    gt.out ==> out;
}

component main = MultiOR(4);
