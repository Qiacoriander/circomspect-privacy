pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/comparators.circom";

// Problem 3: Create a circuit that constrains every element in `in[n]` to be greater than or equal `input k` 
// but also less than or equal `input t`. Constrain that `k < t`.

template Problem3(n) {
    signal input in[n];
    signal input k;
    signal input t;

    component lt = LessThan(252);
    lt.in[0] <== k;
    lt.in[1] <== t;
    lt.out === 1;

    component gtes[n];
    component ltes[n];

    for (var i = 0; i < n; i++) {
        gtes[i] = GreaterEqThan(252);
        gtes[i].in[0] <== in[i];
        gtes[i].in[1] <== k;

        gtes[i].out === 1;

        ltes[i] = LessEqThan(252);
        ltes[i].in[0] <== in[i];
        ltes[i].in[1] <== t;

        ltes[i].out === 1;
    }
}

component main = Problem3(4);