pragma circom 2.0.0;

include "./simple_rsa_verify_v2.circom";
include "../circomlib/circuits/mimcsponge.circom";
include "./compare_public_keys.circom";

// Pkcs1v15 + Sha256
// exp 65537
template GroupRsaVerifyPkcs1v15_v2(w, nb, e_bits, hashLen, npk) {

    signal input publicKeys[npk][2][nb]; //array of known public keys (For each PublicKey, i of npk, you have 2 fields: E,N(modulus) with nb bits)
    signal input sign[nb];    
    signal input hashed[hashLen];
    signal input publicKey[2][nb];
    //out will be the hash of the signature. This allows for a verifiable signature to remain undisclosed, while assuring that the proof won't be reused (same hashes will be ignored after first sucessful verification)
    signal output out;

    //verify signature with given public key
    component SignatureVerification = simple_RsaVerifyPkcs1v15_v2(w, nb, e_bits, hashLen);
    SignatureVerification.exp <== publicKey[0];
    SignatureVerification.sign <== sign;
    SignatureVerification.modulus <== publicKey[1];
    SignatureVerification.hashed <== hashed;

    //verify that public key is part of the group, by having 1 matching key.
    component verifications[npk]; 
    signal interm[npk];

    for (var i=0; i<npk; i++) {
        verifications[i] = ComparePublicKeys(w, nb);
    
        verifications[i].exp_1 <== publicKey[0];
        verifications[i].modulus_1 <== publicKey[1];

        verifications[i].exp_2 <== publicKeys[i][0];
        verifications[i].modulus_2 <== publicKeys[i][1];
    }

    interm[0] <== verifications[0].out;

    for (var i=1; i<npk-1; i++) {
        interm[i] <== interm[i-1]+verifications[i].out;
    }

    interm[npk-1] <== interm[npk-2]+verifications[npk-1].out;

    component groupVerifies = IsEqual();
    groupVerifies.in[0] <== interm[npk-1];
    groupVerifies.in[1] <== 1;

    groupVerifies.out === 1;
        
    //mimc as output guarantees that we don't accept duplicate signatures
    component mimc = MiMCSponge(nb, 220, 1);
    for (var i = 0; i<nb; i++) {
        mimc.ins[i] <== sign[i];
    }
    mimc.k <== 0;
    out <== mimc.outs[0];
 
}

