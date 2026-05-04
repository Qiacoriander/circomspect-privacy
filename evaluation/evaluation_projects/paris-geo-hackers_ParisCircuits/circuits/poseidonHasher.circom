pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";

template PoseidonHasher() {
    signal input in[4];
    signal input hash;
    

    component poseidon = Poseidon(4);
    poseidon.inputs[0] <== in[0];
    poseidon.inputs[1] <== in[1];
    poseidon.inputs[2] <== in[2];
    poseidon.inputs[3] <== in[3];
    hash === poseidon.out;
}

component main{public [hash]}= PoseidonHasher();
