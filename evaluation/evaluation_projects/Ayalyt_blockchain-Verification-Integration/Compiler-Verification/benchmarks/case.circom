pragma circom 2.0.0;

template M() {
    signal input in;
    signal output out;
    out <== in * in;
}


template T() {
    signal input a;
    signal output out1;
    signal output out2;
    component m1 = M();
    component m2 = M();
    m1.in <== a;
    m2.in <== a;
    out1 <== m1.out;
    out2 <== m2.out;
}

component main = T();