pragma circom 2.1.4;

include "node_modules/circomlib/circuits/poseidon.circom";

template MetadataSeal() {
    signal input sender_secret;
    signal input receiver_commitment;
    signal output nullifier;

    component hash = Poseidon(2);
    hash.inputs[0] <== sender_secret;
    hash.inputs[1] <== receiver_commitment;
    nullifier <== hash.out;
}

component main = MetadataSeal();