pragma circom 2.1.8;

include "../node_modules/circomlib/circuits/comparators.circom";

// Problem 4: Create a circuit that forces the following relationship on inputs arrays `input lower[n]`, 
// `input in[n]` and `input upper[n]`: `lower[i] ≤ in[i] ≤ upper[i] for i in 0..n` 
// constrain that `lower[i] < upper[i]` for all `i`.

template Problem4(n) {
    signal input lower[n];
    signal input in[n];
    signal input upper[n];

    component ltes[n];
    component ltes1[n];
    component lts[n];

    for (var i = 0; i < n; i++) {
        ltes[i] = LessEqThan(252);
        ltes[i].in[0] <== lower[i];
        ltes[i].in[1] <== in[i];
        ltes[i].out === 1;

        // One can't reuse ltes here because: Exception caused by invalid assignment: signal already assigned
        ltes1[i] = LessEqThan(252);
        ltes1[i].in[0] <== in[i];
        ltes1[i].in[1] <== upper[i];
        ltes1[i].out === 1;

        lts[i] = LessThan(252);
        lts[i].in[0] <== lower[i];
        lts[i].in[1] <== upper[i];
        lts[i].out === 1;
    }
}

component main = Problem4(4);