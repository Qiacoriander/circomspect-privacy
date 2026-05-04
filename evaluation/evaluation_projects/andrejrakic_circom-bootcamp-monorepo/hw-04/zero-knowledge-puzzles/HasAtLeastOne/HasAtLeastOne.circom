pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/comparators.circom";

// Create a circuit that takes an array of signals `in[n]` and
// a signal k. The circuit should return 1 if `k` is in the list
// and 0 otherwise. This circuit should work for an arbitrary
// length of `in`.

template HasAtLeastOne(n) {
    signal input in[n];
    signal input k;
    signal output out;

    signal products[n + 1];
    products[0] <== 1;

    for (var i = 0; i < n; i++) {
        products[i + 1] <== products[i] * (in[i] - k);
    }

    // Check if the product is 0, meaning at least one of the inputs is equal to k
    component isZero = IsZero();

    isZero.in <== products[n];

    isZero.out ==> out;
}

component main = HasAtLeastOne(4);
