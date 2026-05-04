pragma circom 2.1.6;

template isZero(){
    signal input in;
    signal output out;

    signal inv <-- in == 0 ? 0 : 1/in;
    out <== 1 - in*inv;
    out*in === 0;
}
