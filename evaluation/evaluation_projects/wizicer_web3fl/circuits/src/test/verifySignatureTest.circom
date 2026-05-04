include "../lib/verifySignature.circom";

template VerifySignatureAssert() {
    signal input pubKey[2];
    signal input sig[3];
    signal input msg;


    signal valid;
    valid <== VerifySignature()(pubKey, sig, msg);

    valid === 1;
}

component main { public [pubKey, msg] } = VerifySignatureAssert();
