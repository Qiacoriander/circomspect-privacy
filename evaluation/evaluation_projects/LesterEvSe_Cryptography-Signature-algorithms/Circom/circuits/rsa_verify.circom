pragma circom 2.1.6;

include "helper.circom";
include "../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// Bits for Sha256
template RsaVerify() {
    signal input message[4];
    signal input sign[32];
    signal input pubkey[32];
    signal output IsVerified;

    component res = PowerMod(64, 32, 17);
    for (var i = 0; i < 32; i++) {
        res.base[i] <== sign[i];
        res.modulus[i] <== pubkey[i];
    }

    for (var i = 0; i < 4; i++) {
        message[i] === res.out[i];
    }
    IsVerified <== 1;
}

component main {public [pubkey]} = RsaVerify();