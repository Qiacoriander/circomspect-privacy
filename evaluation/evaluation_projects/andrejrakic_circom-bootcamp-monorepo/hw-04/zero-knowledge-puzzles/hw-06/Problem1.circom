pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/comparators.circom";

// Problem 1: Create a circuit that constrains `in[n]` to be sorted descending

template Problem1(n) {
    signal input in[n];

    component gtes[n - 1];
    
    for (var i = 0; i < n - 1; i++) {
        gtes[i] = GreaterEqThan(252);
        gtes[i].in[0] <== in[i];
        gtes[i].in[1] <== in[i + 1];

        gtes[i].out === 1;
    }
        
}

component main = Problem1(4);
