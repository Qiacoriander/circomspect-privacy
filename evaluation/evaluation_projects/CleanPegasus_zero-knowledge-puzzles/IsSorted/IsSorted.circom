pragma circom 2.1.6;
include "../node_modules/circomlib/circuits/comparators.circom";

// Write a circuit that constrains the 4 input signals to be
// sorted. Sorted means the values are non decreasing starting
// at index 0. The circuit should not have an output.

template IsSorted() {
    signal input in[4];
    signal output out;

    component lte_1 = LessEqThan(252);
    lte_1.in[0] <== in[0];
    lte_1.in[1] <== in[1];

    component lte_2 = LessEqThan(252);
    lte_2.in[0] <== in[1];
    lte_2.in[1] <== in[2];

    component lte_3 = LessEqThan(252);
    lte_3.in[0] <== in[2];
    lte_3.in[1] <== in[3];

    signal a;

    a <== lte_1.out * lte_2.out;
    out <== a * lte_3.out;
    out === 1;

}

component main = IsSorted();
