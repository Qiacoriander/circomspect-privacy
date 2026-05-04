pragma circom 2.0.0;

template T() {
    signal input in[2][3];
    signal output out;
    out <== in[0][0] * in[1][1] + in[1][2];
}

component main = T();