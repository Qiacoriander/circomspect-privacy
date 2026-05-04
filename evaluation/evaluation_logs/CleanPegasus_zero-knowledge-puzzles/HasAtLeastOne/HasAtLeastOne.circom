pragma circom 2.1.6;

// Create a circuit that takes an array of signals `in[n]` and
// a signal k. The circuit should return 1 if `k` is in the list
// and 0 otherwise. This circuit should work for an arbitrary
// length of `in`.

template HasAtLeastOne(n) {
    signal input in[n];
    signal input k;
    signal output out;

    signal isEq[n];

    isEq[0] <== (in[0] - k);

    for(var i = 1; i<n; i++) {
        isEq[i] <== isEq[i - 1] * (in[i] - k);
    }

    out <-- isEq[n - 1] == 0 ? 1 : 0;

}

component main = HasAtLeastOne(4);
