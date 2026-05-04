pragma circom 2.1.6;

template Main() {
    signal input a;
    signal input b;
    signal output c;

    c <== a + b;
}

component main { public [a]} = Main();