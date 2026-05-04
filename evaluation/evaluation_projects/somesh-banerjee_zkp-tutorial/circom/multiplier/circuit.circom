pragma circom 2.1.6;

// Multiplier circuit: basic example from circom documentation

template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;
    c <== a*b;
 }

 component main = Multiplier2();