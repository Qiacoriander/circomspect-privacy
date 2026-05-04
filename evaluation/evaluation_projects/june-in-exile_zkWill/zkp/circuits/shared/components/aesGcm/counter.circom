pragma circom 2.2.2;

include "circomlib/circuits/bitify.circom";
include "galoisField.circom";
include "../arithmetic.circom";
include "../bits.circom";

/**
 * ComputeJ0 for standard 12-byte (96-bit) IV
 * J0 = IV || 0x00000001
 *
 * J0 is the initial counter block in AES-GCM,
 * from which the actual encryption counters (J0+1, J0+2, ...) are derived.
 */
template ComputeJ0Standard() {
    signal input {byte} iv[12];
    signal output {byte} j0[16];
    
    for (var i = 0; i < 12; i++) {
        j0[i] <== iv[i];
    }
    
    (j0[12], j0[13], j0[14], j0[15]) <== (0x00, 0x00, 0x00, 0x01);
}

/**
 * ComputeJ0 for non-standard IV lengths (not 96 bits)
 * Supports IV lengths from 1 to 16 bytes
 * J0 = GHASH_H(IV || 0^s || 0^64 || [len(IV)]64)
 *
 * J0 is the initial counter block in AES-GCM,
 * from which the actual encryption counters (J0+1, J0+2, ...) are derived.
 */
template ComputeJ0NonStandard(ivLengthInBytes) {
    assert(ivLengthInBytes > 0 && ivLengthInBytes <= 64);
    assert(ivLengthInBytes != 12); // Use ComputeJ0Standard for 12-byte IVs
    
    signal input {byte} iv[ivLengthInBytes];
    signal input {byte} hashKey[16];
    signal output {byte} j0[16];
    
    // Calculate padding needed
    var ivLengthInBits = ivLengthInBytes * 8;
    var s = (128 - (ivLengthInBits % 128)) % 128;
    var paddingBytes = s \ 8;
    
    // Calculate total GHASH input length
    // IV + padding + 8 bytes zeros + 8 bytes length
    var totalBytes = ivLengthInBytes + paddingBytes + 8 + 8;
    var numBlocks = totalBytes \ 16;
    assert(numBlocks * 16 == totalBytes);
    
    // Build GHASH input
    signal {byte} ghashInput[numBlocks * 16];
    
    var offset = 0;
    
    // Copy IV
    for (var i = 0; i < ivLengthInBytes; i++) {
        ghashInput[offset + i] <== iv[i];
    }
    offset += ivLengthInBytes;
    
    // Add padding zeros
    for (var i = 0; i < paddingBytes; i++) {
        ghashInput[offset + i] <== 0;
    }
    offset += paddingBytes;
    
    // Add 64 zero bits (8 bytes)
    for (var i = 0; i < 8; i++) {
        ghashInput[offset + i] <== 0;
    }
    offset += 8;
    
    // Add IV length in bits as 64-bit big-endian
    // Since ivLengthInBits <= 512 (2^9), at least upper 48 bits are zero
    for (var i = 0; i < 6; i++) {
        ghashInput[offset + i] <== 0;
    }
    offset += 6;
    
    // Convert ivLengthInBits to big-endian bits
    signal ivLengthBits[16] <== Num2Bits(16)(ivLengthInBits);
    signal ivLengthMSB[8], ivLengthLSB[8];

    for (var i = 0; i < 8; i++) {
        (ivLengthMSB[i], ivLengthLSB[i]) <== (ivLengthBits[i + 8], ivLengthBits[i]);
    }
    (ghashInput[offset], ghashInput[offset + 1]) <== (Bits2Num(8)(ivLengthMSB), Bits2Num(8)(ivLengthLSB));

    // Compute GHASH
    j0 <== GHash(numBlocks)(ghashInput, hashKey);
}

/**
 * @param in - Input 16-byte array representing a counter value
 * @param out - Output 16-byte array with incremented counter value
 * 
 * Increments a 16-byte counter by 1, treating the last 4 bytes as a 32-bit
 * little-endian counter while preserving the first 12 bytes unchanged.
 * 
 * Example: Increment a counter where last 4 bytes represent the count
 *  signal result[16] <== IncrementCounter()([0,0,0,0,0,0,0,0,0,0,0,0,255,255,255,255]);
 *  result[0..11] === [0,0,0,0,0,0,0,0,0,0,0,0];  // First 12 bytes unchanged
 *  result[12..15] === [0,0,0,0];                  // Counter rolled over: 0xFFFFFFFF + 1 = 0x00000000
 */
template IncrementCounter() {
    signal input {byte} in[16];
    signal output {byte} out[16];
    
    for (var i = 0; i < 12; i++) {
        out[i] <== in[i];
    }

    signal {byte} zero <== 0x00;

    signal {bit} carry[5];
    carry[0] <== 1;
    
    for (var i = 0; i < 4; i++) {
        (out[15 - i], carry[i + 1]) <== ByteAdder()(in[15 - i], zero, carry[i]);
    }
}

/**
 * Optimized version that uses direct arithmetic operations instead of cascaded byte adders for better efficiency.
 */
template IncrementCounterOptimized() {
    signal input {byte} in[16];
    signal output {byte} out[16];
    
    for (var i = 0; i < 12; i++) {
        out[i] <== in[i];
    }

    signal counter <== in[12] * 2**24 + in[13] * 2**16 + in[14] * 2**8 + in[15];

    signal bits[33] <== Num2Bits(33)(counter + 1);
    signal bitGroup[4][8];

    for (var i = 0; i < 4; i++) {
        for (var j = 0; j < 8; j++) {
            bitGroup[i][j] <== bits[i * 8 + j];
        }
        out[15 - i] <== Bits2Num(8)(bitGroup[i]);
    }
}

