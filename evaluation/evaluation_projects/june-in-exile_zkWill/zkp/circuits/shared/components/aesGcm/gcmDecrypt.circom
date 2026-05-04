pragma circom 2.2.2;

include "counter.circom";
include "galoisField.circom";
include "ctrEncrypt.circom";
include "../arithmetic.circom";
include "../bus.circom";
include "../bits.circom";

/**
 * Main AES-GCM Decryption Template
 * Based on GcmEncrypt with authTag comparison
 * 
 * @param keyBits - AES key size (128, 192, or 256)
 * @param ivLength - IV length in bytes
 * @param textLengthBytes - Number of bytes to process
 * @param aadLengthBytes - Number of bytes for additional authenticated data
 */
template GcmDecrypt(keyBits, ivLength, textLengthBytes, aadLengthBytes) {
    var Nk;
    assert(keyBits == 128 || keyBits == 192 || keyBits == 256);
    if (keyBits == 128) {
        Nk = 4;
    } else if (keyBits == 192) {
        Nk = 6;
    } else {
        Nk = 8;
    }

    signal input {byte} ciphertext[textLengthBytes];
    input Word() key[Nk];
    signal input {byte} iv[ivLength];
    signal input {byte} authTag[16];
    signal input {byte} aad[aadLengthBytes];
    signal output {byte} plaintext[textLengthBytes];

    // Step 1: Generate hash subkey H = CIPH_K(0^128)
    signal {byte} zeroBlock[16];
    for (var i = 0; i < 16; i++) {
        zeroBlock[i] <== 0;
    }
    signal {byte} hashKey[16] <== EncryptBlock(keyBits)(zeroBlock, key);
    
    // Step 2: Compute J0 based on IV length
    signal {byte} j0[16];
    if (ivLength == 12) {
        // Standard 96-bit IV case: J0 = IV || 0x00000001
        j0 <== ComputeJ0Standard()(iv);
    } else {
        // Non-standard IV length: use GHASH
        j0 <== ComputeJ0NonStandard(ivLength)(iv, hashKey);
    }

    // Step 3: CTR encryption with incremented J0
    plaintext <== CtrEncrypt(keyBits, textLengthBytes)(ciphertext, key, IncrementCounterOptimized()(j0));
    
    // Step 4: Calculate total blocks needed for GHASH input
    var aadNumBlocks = (aadLengthBytes + 15) \ 16;
    var textNumBlocks = (textLengthBytes + 15) \ 16;
    var aadPaddingLengthBytes = (16 - aadLengthBytes % 16) % 16;
    var textPaddingLengthBytes = (16 - textLengthBytes % 16) % 16;
    var totalAuthBlocks = aadNumBlocks + textNumBlocks + 1;
    
    // Step 5: Compute GHASH S = GHASH_H(AAD || 0^v || C || 0^u || [len(AAD)]64 || [len(C)]64)
    // Construct GHASH input
    signal {byte} ghashInput[totalAuthBlocks * 16];
    var offset = 0;
    
    // Add AAD
    for (var i = 0; i < aadLengthBytes; i++) {
        ghashInput[offset + i] <== aad[i];
    }
    offset += aadLengthBytes;
    
    // Add AAD padding
    for (var i = 0; i < aadPaddingLengthBytes; i++) {
        ghashInput[offset + i] <== 0;
    }
    offset += aadPaddingLengthBytes;
    
    // Add ciphertext
    for (var i = 0; i < textLengthBytes; i++) {
        ghashInput[offset + i] <== ciphertext[i];
    }
    offset += textLengthBytes;
    
    // Add ciphertext padding
    for (var i = 0; i < textPaddingLengthBytes; i++) {
        ghashInput[offset + i] <== 0;
    }
    offset += textPaddingLengthBytes;
    
    // Add length information (64-bit big endian)
    var aadLengthBits = aadLengthBytes * 8;
    signal accAadLengthBits[8];
    for (var i = 0; i < 8; i++) {
        ghashInput[offset + i] <-- (aadLengthBits >> 8 * (7 - i)) & 0xFF;
        if (i == 0) {
            accAadLengthBits[i] <== ghashInput[offset + i];
        } else {
            accAadLengthBits[i] <== ghashInput[offset + i - 1] * 2**8 + ghashInput[offset + i];
        }
    }
    accAadLengthBits[7] === aadLengthBits;

    offset += 8;

    var textLengthBits = textLengthBytes * 8;
    signal accTextLengthBits[8];
    for (var i = 0; i < 8; i++) {
        ghashInput[offset + i] <-- (textLengthBits >> 8 * (7 - i)) & 0xFF;
        if (i == 0) {
            accTextLengthBits[i] <== ghashInput[offset + i];
        } else {
            accTextLengthBits[i] <== ghashInput[offset + i - 1] * 2**8 + ghashInput[offset + i];
        }
    }
    accTextLengthBits[7] === textLengthBits;
    
    // Compute GHASH
    signal {byte} S[16] <== GHashOptimized(totalAuthBlocks)(ghashInput, hashKey);
    
    // Step 6: Final tag calculation: T = GCTR_K(J0, S) = S ⊕ CIPH_K(J0)
    signal {byte} tagMask[16] <== EncryptBlock(keyBits)(j0, key);
    signal {byte} expectedAuthTag[16];
    for (var i = 0; i < 16; i++) {
        expectedAuthTag[i] <== BitwiseXor(2, 8)([S[i], tagMask[i]]);
        expectedAuthTag[i] === authTag[i];
    }
}
