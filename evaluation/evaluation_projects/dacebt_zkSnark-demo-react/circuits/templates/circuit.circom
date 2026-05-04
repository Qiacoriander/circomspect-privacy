pragma circom 2.0.2;

include "../packages/circom-ecdsa/circuits/ecdsa.circom";

template SignatureVerification(n, k) {
    // public inputs
    signal input msghash[k];

    // Private inputs
    signal input signatureR[k];
    signal input signatureS[k];
    signal input publicKey[2][k]; // Public key is a 2-element array of 4 64-bit chunks (256 bits each)

    // Verify the signature is valid
    component ecdsaVerify = ECDSAVerifyNoPubkeyCheck(n, k);
    ecdsaVerify.r <== signatureR;
    ecdsaVerify.s <== signatureS;
    ecdsaVerify.pubkey <== publicKey;
    ecdsaVerify.msghash <== msghash;

    // Final result
    signal output verificationResult;
    verificationResult <== ecdsaVerify.result;
}

component main { public [ msghash ] } = SignatureVerification(64, 4);
