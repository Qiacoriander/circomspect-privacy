pragma circom 2.1.9;
include "../node_modules/circomlib/circuits/poseidon.circom";

template hash() {
    signal input a;
    signal input b;
    signal input c;
    signal output N;

    component poseidon = Poseidon(3);
    poseidon.inputs[0] <== a;
    poseidon.inputs[1] <== b;
    poseidon.inputs[2] <== c;
    N <== poseidon.out;
}

component main = hash();
