// 含参数模版
pragma circom 2.0.0;

template Multiplier(M,N) {
    signal input a;
    signal input b;
    signal output c;
    c <== (a *b) * b;
}

component main = Multiplier(5,6);
