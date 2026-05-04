pragma circom 2.1.8;

/*
After Witness generation, i signal can be changed to every other value,
since it is not constaint. Thus providing a fake witness with that is provable
*/

template FakeMul3() {

    signal input a;
    signal input b;
    signal input c;

    signal output out;

    signal i;

    a * b === 1;
    i <-- a * b;
    out <== i * c;
}

component main{public [a, b, c]} = FakeMul3();