pragma circom 2.2.2;

template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;
    c <== a*b;
}

component main = Multiplier2();