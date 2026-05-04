pragma circom 2.0.0;

template Main() {
    signal input a;
    signal output b;
    b <== a;
}

component main = Main();
