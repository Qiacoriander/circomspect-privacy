pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/mimcsponge.circom";

// prove user is owner of private key without revealing private key (preimage)

template verifyUser () {
    signal input secret;
    signal input hash;
    component hasher = MiMCSponge(1,220,1);
    hasher.k <== 0;
    hasher.ins[0] <== secret;
    hasher.outs[0] === hash;
}

component main {public [hash] } = verifyUser();