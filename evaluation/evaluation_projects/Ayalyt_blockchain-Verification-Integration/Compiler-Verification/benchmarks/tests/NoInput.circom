pragma circom 2.0.0;

template K(){
    signal output out;
    out <== 1;
}

template T() {
    signal input in;
    signal output out;
    component k = K();
    out <== in * k.out;
}

component main = T();