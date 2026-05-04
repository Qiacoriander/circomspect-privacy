pragma circom 2.0.0;

include "node_modules\circomlib\circuits\comparators.circom";
template ModuloCheck() {
    signal input x;
    signal input p;
    signal output is_less;

    component lt = LessThan(32);  // Usa comparador de circomlib
    lt.in[0] <== x;
    lt.in[1] <== p;
    is_less <== lt.out;
}

template CircuitoVerificacion() {
    signal input a;
    signal input b;
    signal input p;
    signal output c;

    signal a2 <== a * a;
    signal b2 <== b * b;
    signal suma <== a2 + b2;

    signal k <-- suma \ p;
    signal p_times_k <== p * k;
    signal remainder <== suma - p_times_k;

    component modCheck = ModuloCheck();
    modCheck.x <== remainder;
    modCheck.p <== p;
    modCheck.is_less === 1;

    c <== remainder;
}

component main {public [p]} = CircuitoVerificacion();