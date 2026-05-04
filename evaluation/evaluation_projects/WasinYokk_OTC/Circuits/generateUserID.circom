pragma circom 2.0.0;

include "circomlib-master/circuits/poseidon.circom";

template GenerateUserID() {
    signal input password;
    signal input userSalt;

    signal output userID;

    component poseidon = Poseidon(2);

    poseidon.inputs[0] <== password;
    poseidon.inputs[1] <== userSalt;

    userID <== poseidon.out;
}

component main = GenerateUserID();