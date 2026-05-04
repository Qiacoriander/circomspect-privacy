pragma circom 2.0.0;
include "./node_modules/circomlib/circuits/comparators.circom";

template EqualCheck() {
    signal input a;
    signal input b;
    signal output result;
    signal output publicA;

    // Use the IsZero circuit from circomlib
    component isEqual = IsEqual();
    isEqual.in[0] <== a;
    isEqual.in[1] <== b;

    // Set result
    result <== isEqual.out;
    publicA <== a;
}

component main = EqualCheck();

