pragma circom 2.1.5;


include "../node_modules/circomlib/circuits/sha256/sha256.circom";

template PasswordProof(passwordNBit) {
    signal input passwordBits[passwordNBit]; 
    
    signal input expectedHash[256];

    component hasher = Sha256(passwordNBit);
    for (var i = 0; i < passwordNBit; i++) {
        hasher.in[i] <== passwordBits[i];
    }

    
    for (var i = 0; i < 256; i++) {
        expectedHash[i] === hasher.out[i];
    }
}

component main {public [expectedHash]} = PasswordProof(32);