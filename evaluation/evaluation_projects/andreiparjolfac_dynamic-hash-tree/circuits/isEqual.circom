pragma circom 2.1.6;

include "./isZero.circom";

template isEqual(){
    signal input in[2];
    signal output out;
    component checkZero = isZero();
    checkZero.in<== in[0]-in[1];
    out<==checkZero.out;
}
