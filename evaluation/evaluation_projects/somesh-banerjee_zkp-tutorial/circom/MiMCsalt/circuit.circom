pragma circom 2.1.6;

// MiMCSponge is a cryptographic hash function that is based on the sponge construction, widely used in zero-knowledge proof systems such as zk-SNARKs.

// Input 3 values, a, b and salt. all BigInts

include "../node_modules/circomlib/circuits/mimcsponge.circom";

template Salt() {
    signal input a, b, salt;
    // declare a MiMCSponge component with 2 inputs, 220 rounds and 1 output
    component hash = MiMCSponge(2, 220, 1);
    hash.ins <== [a, b];
    hash.k <== salt;

    signal output out[1] <== hash.outs;
}

component main  = Salt();