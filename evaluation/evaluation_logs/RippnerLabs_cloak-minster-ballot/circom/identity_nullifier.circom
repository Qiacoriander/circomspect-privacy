pragma circom 2.0.4;

include "./node_modules/circomlib/circuits/poseidon.circom";

template IdentityNullifier() {
    signal input identity_secret;
    signal input election_id;

    component poseidon = Poseidon(2);
    poseidon.inputs[0] <== identity_secret;
    poseidon.inputs[1] <== election_id;

    signal output nullifier <== poseidon.out;
}


component main {public [election_id]} = IdentityNullifier();