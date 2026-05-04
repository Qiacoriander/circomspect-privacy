pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/comparators.circom";

// Problem 2: Create a circuit that constrains every element `in[n]` to be greater than `input k`

template Problem2(n) {
    signal input in[n];
    signal input k;

    component gts[n];

    for (var i = 0; i < n; i++) {
        gts[i] = GreaterThan(252);
        gts[i].in[0] <== in[i];
        gts[i].in[1] <== k;

        gts[i].out === 1;
    }
}

component main = Problem2(4);