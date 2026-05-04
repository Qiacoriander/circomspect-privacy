pragma circom 2.0.0;

include "circomlib/circuits/sha256/sha256_2.circom";

template Main() {
    signal input addr; // 输入明文
    signal input secret; // 输入密文
    signal output out; // 输出明文2

    component res = Sha256_2();

    res.a <== addr;
    res.b <== secret;
    out <== res.out;

}

component main {public [addr]} = Main();