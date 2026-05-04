pragma circom 2.1.7;

template expression() {
    signal input a;
    signal input b;
    signal output N;

    signal a2 <== a * a;
    signal a4 <== a2 * a2;
    signal a6 <== a2 * a4;
    N <== a6 + 7 * b * (a2 + b) + 42;
}

component main = expression();
