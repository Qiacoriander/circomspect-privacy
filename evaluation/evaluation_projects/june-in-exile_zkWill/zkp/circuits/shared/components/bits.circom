pragma circom 2.2.2;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/sha256/shift.circom";
include "circomlib/circuits/gates.circom";
include "arithmetic.circom";

/**
 * @param bits - The bit width of the input and mask
 * @param mask - The mask value to apply
 *
 * Example: Extract lower 4 bits using mask
 *  signal masked <== Mask(8,0x0F)(171); // Input:   10101011 (171)
 *                                       // Mask:    00001111  (15)
 *  masked === 11;                       // Result:  00001011  (11)  
 */
template Mask(bits, mask) {
    signal input in;
    signal output out;
    
    signal inBits[bits] <== Num2Bits(bits)(in);
    signal maskBits[bits] <== Num2Bits(bits)(mask);
    signal outBits[bits];

    for (var i = 0; i < bits; i++) {
        outBits[i] <== inBits[i]*maskBits[i];
    }

    out <== Bits2Num(bits)(outBits);
}

/**
 * @param bits - The bit width of the input number
 * @param offset - Number of positions to shift right
 * 
 * Example: Divide by 2^4 using right shift
 *  signal shifted <== ShiftRight(8,4)(171);  // Input: 10101011
 *  shifted === 10;                           // Result: 00001010
 */
template ShiftRight(bits, offset) {
    signal input in;
    signal output out;

    out <== Bits2Num(bits)(ShR(bits,offset)(Num2Bits(bits)(in)));
}

/**
 * N-bit left rotation
 * @param bits - Number of bits (64 for Keccak lanes)
 * @param positions - Number of positions to rotate left
 */
template RotateLeft(bits, positions) {
    signal input in;
    signal output out;

    signal (rightPart, leftPart) <== Divide()(in * 2 ** positions, 2 ** bits);

    out <== leftPart + rightPart;
}

/**
 * @param n - The number of input elements
 * @param bits - The bit width of each input number
 *
 * Example: XOR two 8-bit numbers (i.e., Galois Field addition in GF(2^8))
 *  signal result <== BitwiseXor(2, 8)([170, 85]);  // Input a: 10101010 (170)
 *                                                  // Input b: 01010101  (85)
 *  result === 255;                                 // Result:  11111111 (255)
 *
 * Example: XOR three 8-bit numbers
 *  signal result <== BitwiseXor(3, 8)([15, 51, 85]);  // Input a: 00001111  (15)
 *                                                     // Input b: 00110011  (51)
 *                                                     // Input c: 01010101  (85)
 *  result === 105;                                    // Result:  01101001 (105)
 */
template BitwiseXor(n, bits) {
    assert (n >= 2);
    signal input in[n];
    signal output out;
    
    signal inBits[n][bits];
    for (var i = 0; i < n; i++) {
        inBits[i] <== Num2Bits(bits)(in[i]);
    }
    
    signal outBits[bits];
    signal tempXor[bits][n-1];
    for (var bitIdx = 0; bitIdx < bits; bitIdx++) {
        tempXor[bitIdx][0] <== XOR()(inBits[0][bitIdx], inBits[1][bitIdx]);
        for (var i = 2; i < n; i++) {
            tempXor[bitIdx][i-1] <== XOR()(tempXor[bitIdx][i-2], inBits[i][bitIdx]);
        }
        outBits[bitIdx] <== tempXor[bitIdx][n-2];
    }
    
    out <== Bits2Num(bits)(outBits);
}

/**
 * Optimized version that uses modulo arithmetic instead of chained XOR gates for better efficiency
 *
 * Note: The optimization advantage is most significant when n > 2, as it reduces the number of
 * intermediate constraints compared to chained XOR operations
 */
template BitwiseXorOptimized(n, bits) {
    assert (n > 2);
    signal input in[n];
    signal output out;
    
    signal inBits[n][bits];
    for (var i = 0; i < n; i++) {
        inBits[i] <== Num2Bits(bits)(in[i]);
    }
    
    signal outBits[bits];
    for (var bitIdx = 0; bitIdx < bits; bitIdx++) {
        var tempSum = inBits[0][bitIdx] + inBits[1][bitIdx];
        for (var i = 2; i < n; i++) {
            tempSum += inBits[i][bitIdx];
        }
        outBits[bitIdx] <== Mod2()(tempSum);
    }
    
    out <== Bits2Num(bits)(outBits);
}

/**
 * @param a - First 8-bit input operand
 * @param b - Second 8-bit input operand  
 * @param carry_in - Input carry bit from previous addition
 * @param c - 8-bit sum output (a + b + carry_in) mod 256
 * @param carry_out - Output carry bit (1 if sum >= 256, 0 otherwise)
 * 
 * Example: Add two bytes with carry
 *  signal result, carry <== ByteAdder()(200, 100, 1);  // Input: 200 + 100 + 1 = 301
 *  result === 45;                                      // Result: 301 - 256 = 45
 *  carry === 1;                                        // Carry: 301 >= 256, so carry = 1
 */
template ByteAdder() {
    signal input {byte} a;
    signal input {byte} b;
    signal input {bit} carry_in;
    signal output {byte} c;
    signal output {bit} carry_out;

    signal sum <== a + b + carry_in;

    carry_out <== GreaterEqThan(9)([sum,256]);
    c <== sum - carry_out * 256;    

    _ = Num2Bits(8)(a);
    _ = Num2Bits(8)(b);
    _ = Num2Bits(8)(c);
}

/**
 * Convert an array of bytes to a single 128-bit number
 *
 * @param numBytes - Number of bytes for conversion
 * @param endian - big-endian (0) or little-endian (1)
 * 
 * Example:
 * - Input: [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
 * - Output: 2^127 (big-endian)
 * - Output: 2^7 (litte-endian)
 *
 * - Input: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
 * - Output: 1 (big-endian)
 * - Output: 2^120 (litte-endian)
 */
template BytesToNum(numBytes, endian) {
    assert(endian == 0 || endian == 1);
    signal input {byte} bytes[numBytes];
    signal output num;

    signal intermediateNums[numBytes];
    
    intermediateNums[0] <== bytes[0];
    for (var i = 1; i < numBytes; i++) {
        if (endian == 0) {
            intermediateNums[i] <== intermediateNums[i - 1] * 2**8 + bytes[i];
        } else {
            intermediateNums[i] <== intermediateNums[i - 1] + bytes[i] * 2**(8*i);
        }
    }
    num <== intermediateNums[numBytes - 1];
}

/*
 * Convert a number to an array of bytes
 *
 * @param numBytes - Number of bytes for conversion
 * @param endian - big-endian (0) or little-endian (1)
 * 
 * Example:
 * - Input: 1
 * - Output: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01] (big-endian)
 * - Output: [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] (litte-endian)
 *
 * - Input: 2^127
 * - Output: [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] (big-endian)
 * - Output: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80] (litte-endian)
 */
template NumToBytes(numBytes, endian) {
    assert(endian == 0 || endian == 1);
    signal input num;
    signal output {byte} bytes[numBytes];

    signal intermediateNums[numBytes];
    
    intermediateNums[0] <== num;
    for (var numIdx = 1; numIdx < numBytes; numIdx++) {
        if (endian == 0) {
            (intermediateNums[numIdx], bytes[numBytes - numIdx]) <== Divide()(intermediateNums[numIdx - 1], 2**8);
        } else {
            (intermediateNums[numIdx], bytes[numIdx - 1]) <== Divide()(intermediateNums[numIdx - 1], 2**8);
        }
    }
    bytes[(numBytes - 1) * endian] <== intermediateNums[numBytes - 1];
}

/**
 * Convert an array of bytes to an array of hex char
 *
 * @param bytesLength - Number of bytes
 */
template BytesToHex(bytesLength) {
    signal input {byte} bytes[bytesLength];
    signal output {hex} hex[bytesLength * 2];

    for (var i = 0; i < bytesLength; i++) {
        (hex[i * 2], hex[i * 2 + 1]) <== Divide()(bytes[i], 16);
    }
}

/**
 * Convert an array of hex char to an array of bytes
 *
 * @param bytesLength - Number of bytes
 */
template HexToBytes(bytesLength) {
    signal input {hex} hex[bytesLength * 2];
    signal output {byte} bytes[bytesLength];

    for (var i = 0; i < bytesLength; i++) {
        bytes[i] <== hex[i * 2] * 16 + hex[i * 2 + 1];
    }
}

/**
 * @param numBytes - Number of bytes for conversion
 * @param bitFirst - MSB-first (0) or LSB-first (1)
 *
 * Single byte, MSB-first:
 * 0x80 (10000000₂) → [1,0,0,0,0,0,0,0]
 * 0x01 (00000001₂) → [0,0,0,0,0,0,0,1]
 * 
 * Single byte, LSB-first:
 * 0x80 (10000000₂) → [0,0,0,0,0,0,0,1]
 * 0x01 (00000001₂) → [1,0,0,0,0,0,0,0]
 *
 * 16 bytes, MSB-first:
 * bytes[0] bit 7 → bits[0]
 * bytes[0] bit 6 → bits[1]
 * ...
 * bytes[0] bit 0 → bits[7]
 * bytes[1] bit 7 → bits[8]
 * ...
 * bytes[15] bit 0 → bits[127]
 *
 * 32 bytes, LSB-first:
 * bytes[0] bit 0 → bits[0]
 * bytes[0] bit 1 → bits[1]
 * ...
 * bytes[0] bit 7 → bits[7]
 * bytes[1] bit 0 → bits[8]
 * ...
 * bytes[31] bit 7 → bits[255]
 */
template BytesToBits(numBytes, bitFirst) {
    assert(bitFirst == 0 || bitFirst == 1);
    signal input {byte} bytes[numBytes];
    signal output {bit} bits[numBytes * 8];
    
    component byteToBits[numBytes];
    
    for (var byteIdx = 0; byteIdx < numBytes; byteIdx++) {
        byteToBits[byteIdx] = Num2Bits(8);
        byteToBits[byteIdx].in <== bytes[byteIdx];
        
        for (var bitIdx = 0; bitIdx < 8; bitIdx++) {
            if (bitFirst == 0) {
                bits[byteIdx * 8 + bitIdx] <== byteToBits[byteIdx].out[7 - bitIdx];
            } else {
                bits[byteIdx * 8 + bitIdx] <== byteToBits[byteIdx].out[bitIdx];
            }
        }
    }
}

/**
 * @param numBytes - Number of bytes for conversion
 * @param bitFirst - MSB-first (0) or LSB-first (1)
 *
 * Single byte, MSB-first:
 * [1,0,0,0,0,0,0,0] → 0x80 (10000000₂)
 * [0,0,0,0,0,0,0,1] → 0x01 (00000001₂)
 * 
 * Single byte, LSB-first:
 * [0,0,0,0,0,0,0,1] → 0x80 (10000000₂)
 * [1,0,0,0,0,0,0,0] → 0x01 (00000001₂)
 *
 * 16 bytes, MSB-first:
 * bits[0] → bytes[0] bit 7
 * bits[1] → bytes[0] bit 6
 * ...
 * bits[7] → bytes[0] bit 0
 * bits[8] → bytes[1] bit 7
 * ...
 * bits[127] → bytes[15] bit 0
 *
 * 32 bytes, LSB-first:
 * bits[0] → bytes[0] bit 0
 * bits[1] → bytes[0] bit 1
 * ...
 * bits[7] → bytes[0] bit 7
 * bits[8] → bytes[1] bit 0
 * ...
 * bits[255] → bytes[31] bit 7
 */ 
template BitsToBytes(numBytes, bitFirst) {
    signal input {bit} bits[numBytes * 8];
    signal output {byte} bytes[numBytes];
    
    component bitsToBytes[numBytes];
    
    for (var byteIdx = 0; byteIdx < numBytes; byteIdx++) {
        bitsToBytes[byteIdx] = Bits2Num(8);
        
        for (var bitIdx = 0; bitIdx < 8; bitIdx++) {
            if (bitFirst == 0) {
                bitsToBytes[byteIdx].in[7 - bitIdx] <== bits[byteIdx * 8 + bitIdx];
            } else {
                bitsToBytes[byteIdx].in[bitIdx] <== bits[byteIdx * 8 + bitIdx];
            }
        }
        
        bytes[byteIdx] <== bitsToBytes[byteIdx].out;
    }
}