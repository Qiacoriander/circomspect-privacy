pragma circom 2.0.3;

include "hash_and_blind.circom";
include "aes/ctr.circom";
/**
 * Combines SHA-256 hashing of an input byte sequence with RSA-PSS blinding.
 * @param messageLen  The length of the input message in bytes.
 */
template TLSAesSha(messageLen, nk) {

    // Inputs
    signal input message[messageLen];    // message to hash
    signal input iv[16];                // AES CTR IV
    signal input key[nk * 4];           // AES key (nk * 4 bytes, e.g., nk=4 for 128-bit key)

    // Output
    signal output cipher[messageLen];   // encrypted message

    // 0) Hash the message
    component hasher = Sha256Bytes(messageLen);
    for (var i = 0; i < messageLen; i++) {
        hasher.in[i] <== message[i];
    }

    // 3) Encrypt the blinded output using AES CTR
    
    component aes = EncryptCTR(messageLen, nk);
    for (var i = 0; i < messageLen; i++) {
        aes.plainText[i] <== message[i];
    }
    for (var i = 0; i < 16; i++) {
        aes.iv[i] <== iv[i];
    }
    for (var i = 0; i < nk*4; i++) {
        aes.key[i] <== key[i];
    }
    for (var i = 0; i < messageLen; i++) {
        cipher[i] <== aes.cipher[i];
    }


}

component main = TLSAesSha({{MESSAGE_LEN}}, 4);