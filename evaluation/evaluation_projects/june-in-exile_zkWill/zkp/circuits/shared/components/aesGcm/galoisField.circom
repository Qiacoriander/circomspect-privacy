pragma circom 2.2.2;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/gates.circom";
include "../arithmetic.circom";
include "../bits.circom";

/**
 * Galois Field multiplication by 2 in GF(2^8) with reduction polynomial x^8 + x^4 + x^3 + x + 1 (0x11b in MSB order)
 * 
 * Algorithm:
 * 1. Left shift the input by 1 bit
 * 2. If the original value had bit 7 set (>= 0x80), XOR with 0x1b
 */
template GF8Mul2() {
    signal input {byte} in;
    signal output {byte} out;

    // Extract the most significant bit (bit 7)
    signal bits[8] <== Num2Bits(8)(in);
    signal msb <== bits[7];
    
    // Left shift by 1 and mask to keep only lower 8 bits
    signal shifted <== Mask(9,0xff)(in * 2);
    
    // Apply polynomial reduction if MSB was set
    out <== BitwiseXor(2,8)([shifted, msb * 0x1b]);
}

/**
 * Galois Field multiplication by 3 in GF(2^8)
 * 
 * Algorithm: 3 * x = (2 * x) ⊕ x
 */
template GF8Mul3() {
    signal input {byte} in;
    signal output {byte} out;
    
    signal mul2 <== GF8Mul2()(in);
    
    out <== BitwiseXor(2,8)([mul2,in]);
}

/**
 * Galois Field multiplication in GF(2^128) with reduction polynomial x^128 + x^7 + x^2 + x + 1 (0xe1 || 30 zeros in LSB-first order)
 *
 * Idea of Galois Field multiplication with reduction polynomial p(x):
 *   c = Σ (a[i] == 1 ? b >> i : 0) mod p(x)
 *
 * Algorithm:
 * - For each bit i of 'a' (from LSB to MSB):
 *   - If a[i] == 1, c ^= b
 *   - b >>= 1
 *   - If b overflows, reduce using the polynomial
 */
template GF128Multiply() {
    signal input {byte} aBytes[16];
    signal input {byte} bBytes[16];
    signal output {byte} cBytes[16];
    
    signal {bit} aBits[128];
    signal {bit} bBits[129][128];
    signal {bit} cBits[129][128];

    // Convert 16-byte a, b to 128-bit, initialize c = 0
    aBits <== BytesToBits(16, 0)(aBytes);
    bBits[0] <== BytesToBits(16, 0)(bBytes);

    for (var bit = 0; bit < 128; bit++) {
        cBits[0][bit] <== 0;
    }
    
    // Process each bit of 'a' from MSB to LSB
    for (var round = 1; round <= 128; round++) {
        for (var bit = 0; bit < 128; bit++) {
            // Step 1: If a[round-1] == 1, XOR current b into c
            // c = c ⊕ (a[round-1] ? b : 0)
            cBits[round][bit] <== XOR()(cBits[round - 1][bit], aBits[round - 1] * bBits[round - 1][bit]);
            
            // Step 2: Right shift b by 1 bit (equivalent to multiplying by x)
            // Handle the reduction polynomial when MSB overflows
            // By XOR it into positions 0, 1, 2, 7
            if (bit == 0) {
                // bBits[round - 1][127] is the carry
                bBits[round][bit] <== bBits[round - 1][127];
            } else if (bit == 1 || bit == 2 || bit == 7) {
                bBits[round][bit] <== XOR()(bBits[round - 1][127], bBits[round - 1][bit - 1]);
            } else {
                bBits[round][bit] <== bBits[round - 1][bit - 1];
            }
        }
    }

    // Convert final result bits back to bytes
    cBytes <== BitsToBytes(16, 0)(cBits[128]);
}

/**
 * Optimized Galois Field multiplication in GF(2^128)
 * Reduction polynomial: x^128 + x^7 + x^2 + x + 1
 * 
 * This implementation uses a three-round approach to handle overflows efficiently:
 * - Round 1: Calculate initial multiplication with first-level overflows
 * - Round 2: Process first-level overflows with reduction polynomial
 * - Round 3: Process remaining second-level overflows
 * 
 * The key optimization is accumulating contributions instead of iterative XOR operations,
 * which significantly reduces the number of constraints.
 *
 * Demonstration of the Algorithm with GF(2^8):
 *  
 *     signal input {bit} a[8] = 10010001 (0x91);
 *     signal input {bit} b[8] = 11101111 (0xef);
 *     signal output {bit} c[8];
 *
 *     p(x) = 1 + x + x^3 + x^4 -> p_x = [0,1,3,4]
 *
 *     ====================== Round 1 ======================
 *
 *   ctr1[8][8]:
 *
 *         bBit 0  1  2  3  4  5  6  7
 *    aBit                            ..7
 *       0      1  1  1  0  1  1  1  1   ..7
 *       1         1  1  0  1  1  1  1  0   ..7
 *       2            1  0  1  1  1  1  0  0   ..7
 *       3               1  2  2  1  2  1  1  1   ..7
 *       4                  2  2  1  2  1  1  1  0   ..7
 *       5                     2  1  2  1  1  1  0  0   ..7
 *       6                        1  2  1  1  1  0  0  0   
 *       7                           3  2  2  1  1  1  1  1
 *              ______________________  ___________________
 *  contr1:     1  1  1  1  2  2  1  3, ctr2[0]
 *
 *     ====================== Round 2 ======================
 *
 *   ctr2[4][7]:
 *
 *         bit  0  1  2  3  4  5  6
 *    pIdx                         ..6
 *       0      2  2  1  1  1  1  1   ..5  6
 *       1         4  3  2  2  2  2  1      ..6
 *       2               4  4  3  3  2  1  1   
 *       3                  6  5  4  3  2  2  1
 *              ______________________  _______
 *  contr2:     2  4  3  4  6  5  4  3, ctr3[0]
 *
 *     ====================== Round 3 ======================
 *
 *   ctr3[4][3]:
 *
 *         bit  0  1  2
 *    pIdx             ..2
 *       0      2  2  1   ..1  2
 *       1         4  3  1      ..2
 *       2               3  2  1   
 *       3                  4  3  1
 *              ___________________
 *  contr3:     2  4  3  3  4  3  1
 *
 *     ===================== Sum & Mod =====================
 *
 *   contr1     1  1  1  1  2  2  1  3
 * + contr2     2  4  3  4  6  5  4  3
 * + contr3     2  4  3  3  4  3  1
 * =    sum     5  9  7  8 12 10  6  6
 * 
 *    mod2:     1  1  1  0  0  0  0  0
 *      c =     11100000 (0xe0)
 */
template GF128MultiplyOptimized() {
    signal input {byte} aBytes[16];
    signal input {byte} bBytes[16];
    signal output {byte} cBytes[16];
    
    signal {bit} aBits[128];
    signal {bit} bBits[128];
    signal {bit} cBits[128];

    // Reduction polynomial coefficients: 1 + x + x^2 + x^7
    var p_x[4] = [0, 1, 2, 7];

    // Counter arrays for accumulating contributions
    signal counter1[128][128];
    signal counter2[4][127];    // Maximum 127 overflow bits from round 1
    signal counter3[4][6];      // Maximum 6 overflow bits from round 2

    // Convert 16-byte a, b to 128-bit
    aBits <== BytesToBits(16, 0)(aBytes);
    bBits <== BytesToBits(16, 0)(bBytes);

    // ===== Round 1: Main multiplication =====
    // For each bit of 'a', accumulate b shifted right by that bit position
    for (var aBit = 0; aBit < 128; aBit++) {
        for (var bBit = 0; bBit < 128; bBit++) {
            var prevBBit = bBit + 1;
            // Base case: first a-bit or no previous b-bit to carry
            if (aBit == 0 || prevBBit >= 128) {
                counter1[aBit][bBit] <== aBits[aBit] * bBits[bBit];
            } else {
                // Accumulate: current contribution + carried value from previous iteration
                counter1[aBit][bBit] <== counter1[aBit - 1][prevBBit] + aBits[aBit] * bBits[bBit];
            }
        }
    }

    // ===== Round 2: Process first-level overflows =====
    // Initialize with overflow bits (128+) from round 1
    for (var i = 0; i < 127; i++) {
        counter2[0][i] <== counter1[127][i + 1];
    }

    // Apply reduction polynomial to overflow bits from round 1
    for (var pIdx = 1; pIdx < 4; pIdx++) {
        // Accumulate from previous polynomial term if it exists
        var offset = p_x[pIdx] - p_x[pIdx - 1];
        for (var bit = 0; bit < 127; bit++) {
            var prevTerm = (bit < 127 - offset) ? counter2[pIdx - 1][bit + offset] + counter2[0][bit] : counter2[0][bit];
            counter2[pIdx][bit] <== prevTerm;
        }
    }

    // ===== Round 3: Process second-level overflows =====
    // Initialize with overflow bits (128+) from round 2
    for (var i = 0; i < 6; i++) {
        counter3[0][i] <== counter2[3][i + (128 - 7)];
    }

    // Apply reduction polynomial to remaining overflow bits
    for (var pIdx = 1; pIdx < 4; pIdx++) {
        // Accumulate from previous polynomial term if it exists
        var offset = p_x[pIdx] - p_x[pIdx - 1];
        for (var bit = 0; bit < 6; bit++) {
            var prevTerm = (bit < 6 - offset) ? counter3[pIdx - 1][bit + offset] + counter3[0][bit] : counter3[0][bit];
            counter3[pIdx][bit] <== prevTerm;
        }
    }
    
    // ===== Final step: Sum all contributions and reduce modulo 2 =====
    for (var cBit = 0, contribution1, contribution2, contribution3; cBit < 128; cBit++) {
        contribution1 = counter1[cBit][0];
        if (cBit < p_x[1]) {
            (contribution2, contribution3) = (counter2[0][cBit - p_x[0]], counter3[0][cBit - p_x[0]]);
        } else if (cBit < p_x[2]) {
            (contribution2, contribution3) = (counter2[1][cBit - p_x[1]], counter3[1][cBit - p_x[1]]);
        } else if (cBit < p_x[3]) {
            (contribution2, contribution3) = (counter2[2][cBit - p_x[2]], counter3[2][cBit - p_x[2]]);
        } else {
            // Only bits 0-12 can have contributions from round 3
            (contribution2, contribution3) = (counter2[3][cBit - p_x[3]], (cBit < 13) ? counter3[3][cBit - p_x[3]] : 0);
        }
        cBits[cBit] <== Mod2()(contribution1 + contribution2 + contribution3);
    }

    // Convert final result bits back to bytes
    cBytes <== BitsToBytes(16, 0)(cBits);
}

/**
 * GHASH function for AES-GCM (Standard Implementation)
 * Processes fixed-length input (must be padded to multiple of 16 bytes)
 * 
 * GHASH is a universal hash function used in AES-GCM mode for authentication.
 * It operates over the Galois Field GF(2^128) and processes data in 16-byte blocks.
 * 
 * Algorithm: For each block B_i, compute: Y_i = (Y_{i-1} ⊕ B_i) * H
 * where H is the hash key and Y_0 = 0
 * 
 * @param numBlocks - Number of 16-byte blocks to process
 */
template GHash(numBlocks) {
    signal input {byte} data[numBlocks * 16];
    signal input {byte} hashKey[16];
    signal output {byte} result[16];
    
    // Intermediate results for each block
    signal {byte} intermediateResults[numBlocks + 1][16];
    
    // Initialize with zeros
    for (var i = 0; i < 16; i++) {
        intermediateResults[0][i] <== 0;
    }
    
    // Process each 16-byte block
    signal {byte} xorResult[numBlocks][16];
    for (var block = 0; block < numBlocks; block++) {
        // XOR current result with data block
        for (var i = 0; i < 16; i++) {
            xorResult[block][i] <== BitwiseXor(2, 8)([intermediateResults[block][i], data[block * 16 + i]]);
        }
        
        // Multiply by hashKey in GF(2^128)
        intermediateResults[block + 1] <== GF128MultiplyOptimized()(xorResult[block], hashKey);
    }
    
    // Output final result
    result <== intermediateResults[numBlocks];
}

/**
 * Optimization: Instead of storing initial zero state, directly use the first
 * data block without XOR for the first iteration, saving one intermediate array slot.
 * This is mathematically equivalent since 0 ⊕ B_0 = B_0.
 */
template GHashOptimized(numBlocks) {
    signal input {byte} data[numBlocks * 16];
    signal input {byte} hashKey[16];
    signal output {byte} result[16];
    
    // Process each 16-byte block
    signal {byte} xorResult[numBlocks][16];
    signal {byte} intermediateResults[numBlocks][16];

    for (var block = 0; block < numBlocks; block++) {
        // XOR current result with data block
        for (var i = 0; i < 16; i++) {
            if (block == 0) {
                xorResult[0][i] <== data[i];
            } else {
                xorResult[block][i] <== BitwiseXor(2, 8)([intermediateResults[block - 1][i], data[block * 16 + i]]);
            }
        }
        // Multiply by hashKey in GF(2^128)
        intermediateResults[block] <== GF128MultiplyOptimized()(xorResult[block], hashKey);
    }
    
    // Output final result
    result <== intermediateResults[numBlocks - 1];
}