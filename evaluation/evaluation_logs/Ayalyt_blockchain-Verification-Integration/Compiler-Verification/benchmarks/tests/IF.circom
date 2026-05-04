pragma circom 2.0.0;


template T() {
    signal input a;
    signal input b;
    signal output out1;
    signal output out2;
    signal output out3;
    signal temp;
    out1 <== a;
    if(a > 0) {
        out2 <-- a * a;
    }

    out3 <== out2;
}

component main {public [b]}= T();