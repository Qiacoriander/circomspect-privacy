// 模版调用
pragma circom 2.0.0;

template A(M) {
    signal input in;
    signal output out;
    out <== in;
}

template B(N) {
    signal output out;
    component a,b=A(1);
    a = A(5);
}

component main = B(1);
