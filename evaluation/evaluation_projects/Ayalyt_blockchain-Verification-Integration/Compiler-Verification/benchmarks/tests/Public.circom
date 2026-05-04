pragma circom 2.0.0;

template T() {
    signal input in1;
    signal input in2;
    signal input in3;
    signal output out;
    out <== in1 * in2 + in3;
}

component main {public [in1, in2]} = T();