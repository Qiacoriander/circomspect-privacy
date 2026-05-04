// 多个模版
pragma circom 2.0.0;

template A() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
}

template C(x,y) {
    signal input d;
    signal input e;
    signal output f;
    e <== d * f;
}

template B(N) {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
}

component main = B(2);
