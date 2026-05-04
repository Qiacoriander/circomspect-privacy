pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/mimc.circom";

template MultiMiMCN() {
    signal input a;
    signal input b;
    signal output out;

    component hasher = MultiMiMC7(2, 91);
    hasher.in[0] <== a;
    hasher.in[1] <== b;
    hasher.k <== 1;
    out <== hasher.out;
}

component main = MultiMiMCN();
