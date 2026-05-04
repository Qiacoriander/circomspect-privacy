pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";

template SafeCircuit() {
    signal input secret;          // 私有线索
    signal input div;
    signal input hash_expected;   // 唯一公信号

    // 一些非线性运算 + 除法结构
    signal a;
    signal b;
    signal c;
    signal d;

    a <== secret / div;
    b <== a * a * a;
    c <== b;
    d <== c - secret;

    // ---- Poseidon ----
    component h = Poseidon(1);
    h.inputs[0] <== c;
    h.out === hash_expected;

}

component main {public [secret, hash_expected]} = SafeCircuit();
