pragma circom 2.2.2;

include "ctrEncrypt.circom";

/**
 * AES CTR Mode Decryption Circuit
 * Based on CtrEncrypt
 * 
 * @param keyBits - AES key size in bits (128, 192, or 256)
 * @param ciphertextBytes - Number of bytes to decrypt
 */
template CtrDecrypt(keyBits, ciphertextBytes) {
    var Nk;
    assert(keyBits == 128 || keyBits == 192 || keyBits == 256);
    if (keyBits == 128) {
        Nk = 4;
    } else if (keyBits == 192) {
        Nk = 6;
    } else {
        Nk = 8;
    }
    
    signal input {byte} ciphertext[ciphertextBytes]; // Ciphertext data in bytes
    input Word() key[Nk]; // AES key using Word bus structure
    signal input {byte} iv[16]; // Initial counter value
    signal output {byte} plaintext[ciphertextBytes]; // Decrypted output

    plaintext <== CtrEncrypt(keyBits, ciphertextBytes)(ciphertext, key, iv);
}