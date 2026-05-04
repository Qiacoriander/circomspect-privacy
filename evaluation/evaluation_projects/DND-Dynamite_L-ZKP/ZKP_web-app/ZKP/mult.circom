pragma circom 2.1.6;

template Mult() {
    signal input a;     // private
    signal input b;     // private
    signal output c;    // public

    c <== a * b;        // constraint + witness generation
}

component main = Mult();