pragma circom 2.1.8;
include "comparators.circom";
include "multiplexer.circom";

// https://akosba.github.io/papers/xjsnark.pdf

template QuitSelector(n) {
    signal input numbers[n];
    signal input index;
    signal output out;

    signal upper <== LessThan(252)([index, n]);
    upper  === 1;
    signal lower <== GreaterEqThan(252)([index, 0]);
    lower === 1;

    component innerProduct = EscalarProduct(n);
    component isEqual[n];
    for(var i = 0; i < n; i++) {
        isEqual[i] = IsEqual();
        isEqual[i].in[0] <== i;
        isEqual[i].in[1] <== index;
        innerProduct.in1[i] <== isEqual[i].out;
        innerProduct.in2[i] <== numbers[i];
    }
    out <== innerProduct.out;
}

component main = QuitSelector(3);
