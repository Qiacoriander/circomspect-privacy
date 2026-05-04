pragma circom 2.0.0;

template M(a, b) {
    signal input in[a];     // if array size is not constant, raise error directly
    signal output out;
    out <== in[0] * in[1] + b;
}


template T() {
    signal input in1;
    signal input in2;
    signal output out1;
    signal output out2;
    signal output out3;
    component m1 = M(2,1);
    component m2 = M(2,3);
    m1.in[0] <== in1;
    m1.in[1] <== in2;
    m2.in[0] <== in1;
    m2.in[1] <== in1;
    out1 <== m1.out;
    out2 <== m2.out;
}

component main = T();
    