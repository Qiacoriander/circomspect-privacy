pragma circom 2.0.0;

template Multiplier2() {
    signal input a;     // public input - minAge
    signal input b;     // private input - userAge
    signal output c;    // public output - result

    // Circuit logic: c = a * b
    c <== a * b;
}

component main {public [a]} = Multiplier2();
