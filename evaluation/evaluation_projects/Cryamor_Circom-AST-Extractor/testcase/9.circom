// 函数与模版混合与调用
pragma circom 2.0.0;

template Multiplier() {
   signal input a;
   signal input b;
   signal output c;
   c <== nn(b);
}

function nn(a) {
    return a+1;
}

template Multiplier2() {
   signal input a;
   signal input b;
   signal output c;
   c <== nn(b);
}

function mm(a) {
    return a+1;
}

component main = Multiplier();
