pragma circom 2.2.2;

include "counter.circom";
include "encryptBlock.circom";
include "../bus.circom";
include "../bits.circom";

/**
 * AES CTR Mode Encryption Circuit
 * Implements the Counter (CTR) mode of operation for AES encryption
 * Following NIST SP 800-38A standard for counter mode
 * 
 * CTR mode converts AES block cipher into a stream cipher by:
 * 1. Incrementing a counter for each block
 * 2. Encrypting the counter with AES
 * 3. XORing the result with plaintext
 * 
 * @param keyBits - AES key size in bits (128, 192, or 256)
 * @param plaintextBytes - Number of bytes to encrypt
 */
template CtrEncrypt(keyBits, plaintextBytes) {
    var Nk;
    assert(keyBits == 128 || keyBits == 192 || keyBits == 256);
    if (keyBits == 128) {
        Nk = 4;
    } else if (keyBits == 192) {
        Nk = 6;
    } else {
        Nk = 8;
    }
    
    signal input {byte} plaintext[plaintextBytes]; // Plaintext data in bytes
    input Word() key[Nk]; // AES key using Word bus structure
    signal input {byte} iv[16]; // Initial counter value
    signal output {byte} ciphertext[plaintextBytes]; // Encrypted output

    var numBlocks = (plaintextBytes + 15) \ 16;
    
    if (numBlocks > 0) {
        // Counter state array - stores counter value for each block
        signal {byte} counters[numBlocks][16];

        counters[0] <== iv;
    
        // Generate incremented (for last 4 bytes only) counters for each block
        for (var block = 1; block < numBlocks; block++) {
            counters[block] <== IncrementCounterOptimized()(counters[block - 1]);
        }
        
        // Encrypt each counter to generate keystream
        signal {byte} keystreams[numBlocks][16];
        for (var block = 0; block < numBlocks; block++) {
            keystreams[block] <== parallel EncryptBlock(keyBits)(counters[block], key);
        }
        
        // XOR plaintext with keystream to produce ciphertext
        for (var byte = 0; byte < plaintextBytes; byte++) {
            ciphertext[byte] <== BitwiseXor(2, 8)([plaintext[byte], keystreams[byte \ 16][byte % 16]]);
        }
    }
}