pragma circom 2.0.0;
include "poseidon.circom"; 

template ComputeNullifier() {
    signal input secret;
    signal input unsafeRandom;

    signal output nullifier;

    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== secret;
    poseidon.inputs[1] <== unsafeRandom;
    nullifier <== poseidon.out;
}

