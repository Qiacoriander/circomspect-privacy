pragma circom 2.0.0;

include "./simple_rsa_verify.circom";
include "../circomlib/circuits/mimcsponge.circom";

// Pkcs1v15 + Sha256
// exp 65537
template GroupRsaVerifyPkcs1v15(w, nb, e_bits, hashLen, npk) {

    signal input publicKeys[npk][2][nb]; //array of known public keys (For each PublicKey, i of npk, you have 2 fields: E,N(modulus) with nb bits)
    signal input sign[nb];    
    signal input hashed[hashLen];
    //out will be the hash of the signature. This allows for a verifiable signature to remain undisclosed, while assuring that the proof won't be reused (same hashes will be ignored after first sucessful verification)
    signal output out;

    component verifications[npk]; //verification of signature with all i of npk public keys

    for (var i = 0; i<npk; i++) {
        verifications[i] = simple_RsaVerifyPkcs1v15(w, nb, e_bits, hashLen);
        verifications[i].exp <== publicKeys[i][0];
        verifications[i].sign <== sign;
        verifications[i].modulus <== publicKeys[i][1];
        verifications[i].hashed <== hashed;
    }

    signal interm[npk];
    interm[0] <== verifications[0].out;

    for (var i = 1; i<npk; i++) {
        interm[i] <== interm[i-1]+verifications[i].out;
    }

    interm[npk-1] === 1;

    component mimc = MiMCSponge(nb, 220, 1);
    for (var i = 0; i<nb; i++) {
        mimc.ins[i] <== sign[i];
    }
    mimc.k <== 0;
    out <== mimc.outs[0];


    
}

