pragma circom 2.1.5;

include "./rsa-circuit/circuits/rsa.circom";

template RsassaPssSha256SignatureVerifier(N, K) {
    var SHA256_LEN = 256;

    // not necessary for this poc, but chunkedDecryptedSig comes from this hash
    signal input hash[SHA256_LEN];
    signal input sig[K];
    signal input mod[K];
    signal input chunkedDecryptedSig[K];
    signal output a;

    component rsaVerify = RSAVerify65537(N, K);
    for(var i=0; i<K; i++) {
        rsaVerify.signature[i] <== sig[i];
        rsaVerify.modulus[i] <== mod[i];
        rsaVerify.base_message[i] <== chunkedDecryptedSig[i];
    }
}

component main = RsassaPssSha256SignatureVerifier(120, 35);
