pragma circom 2.1.4;

template Add() {
    signal input in[3];

    in[0] === in[1] + in[2];
}

/*
Alternative method to add numbers
template Add(){
    signal input a;
    signal input b;
    signal output c;

    c <== a + b;
}
*/

component main  = Add();