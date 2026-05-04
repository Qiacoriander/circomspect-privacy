pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/babyjub.circom";

template pk(n) {
    assert(n<253);
    signal input privateKey;
    signal input publicKey[2];

    component babyPbk = BabyPbk();
    babyPbk.in <== privateKey;
    
    publicKey[0] === babyPbk.Ax;
    publicKey[1] === babyPbk.Ay;
}

component main {public [publicKey]} = pk(252);