pragma circom 2.2.2;

include "circomlib/circuits/gates.circom";
include "circomlib/circuits/multiplexer.circom";
include "galoisField.circom";
include "../bus.circom";
include "../bits.circom";

template RotWord() {
    input Word() in;
    output Word() out;
    
    for (var i = 0; i < 4; i++) {
        out.bytes[i] <== in.bytes[(i + 1) % 4];
    }
}

template XorWord() {
    input Word() a;
    input Word() b;
    output Word() c;
    
    signal _a[4] <== a.bytes;
    signal _b[4] <== b.bytes;
    for (var i = 0; i < 4; i++) {
        c.bytes[i] <== BitwiseXor(2,8)([_a[i],_b[i]]);
    }
}

template RCon() {
    signal input round;
    output Word() out;

    var wIn = 1, nIn = 10;

    var roundConstants[nIn][wIn] = [
        [0x01],[0x02],[0x04],[0x08],
        [0x10],[0x20],[0x40],[0x80],
        [0x1b],[0x36]
    ];
    
    signal {byte} outs[wIn] <== Multiplexer(wIn,nIn)(roundConstants,round);
    out.bytes <== [outs[0], 0, 0 , 0];
}

/**
 * FIPS 197 AES 5.2 KEYEXPANSION()
 * 
 * Symbols:
 *   Nk: the key size in words
 *   Nb: the block size in words
 *   Nr: the number of rounds
 *   key[i...i+3]: the sequence key[i],key[i+1],key[i+2],key[i+3]. 
 *   w[i]: the i-th word (a total of 4*Nr+4=60 words).
 *
 * Key-Block-Round Combinations:
 *           Nk(words) Nb(words) Nr(rounds)
 * AES-128      4          4         10
 * AES-192      6          4         12
 * AES-256      8          4         14
 *
 * Key expansion rule:
 *   for i < Nk:
 *     w[i] = key[4*i...4*i+3]
 *   for i >= Nk:
 *     if (i mod Nk == 0)
 *       w[i] = w[i - Nk] ⊕ SubWord(RotWord(w[i - 1])) ⊕ Rcon[i / Nk]
 *     else if (Nk > 6 and i mod Nk == 4)
 *       w[i] = w[i - Nk] ⊕ SubWord(w[i - 1])
 *     else
 *       w[i] = w[i - Nk] ⊕ w[i - 1]
 */
template ExpandKey(keyBits) {
    var (Nk, Nb, Nr);
    assert(keyBits == 128 || keyBits == 192 || keyBits == 256);
    if (keyBits == 128) {
        (Nk, Nb, Nr) = (4,4,10);
    } else if (keyBits == 192) {
        (Nk, Nb, Nr) = (6,4,12);
    } else {
        (Nk, Nb, Nr) = (8,4,14);
    }
    var expandedNk = 4 * (Nr + 1);

    input Word() key[Nk];
    output Word() roundKey[expandedNk];

    for (var i = 0; i < Nk; i++) {
        roundKey[i] <== key[i];
    }
    for (var i = Nk; i < expandedNk; i++) {
        if (i % Nk == 0) {
            roundKey[i] <== XorWord()(roundKey[i-Nk], XorWord()(SubWord()(RotWord()(roundKey[i-1])), RCon()((i\Nk)-1)));
        } else if (Nk > 6 && i % Nk == 4) {
            roundKey[i] <== XorWord()(roundKey[i-Nk], SubWord()(roundKey[i-1]));
        } else {
            roundKey[i] <== XorWord()(roundKey[i-Nk], roundKey[i-1]);
        }
    }
}

template SBox() {
    signal input {byte} in;
    signal output {byte} out;

    var wIn = 1, nIn = 256;

    var substitutionBox[nIn][wIn] = [
        [0x63], [0x7c], [0x77], [0x7b], [0xf2], [0x6b], [0x6f], [0xc5],
        [0x30], [0x01], [0x67], [0x2b], [0xfe], [0xd7], [0xab], [0x76],
        [0xca], [0x82], [0xc9], [0x7d], [0xfa], [0x59], [0x47], [0xf0],
        [0xad], [0xd4], [0xa2], [0xaf], [0x9c], [0xa4], [0x72], [0xc0],
        [0xb7], [0xfd], [0x93], [0x26], [0x36], [0x3f], [0xf7], [0xcc],
        [0x34], [0xa5], [0xe5], [0xf1], [0x71], [0xd8], [0x31], [0x15],
        [0x04], [0xc7], [0x23], [0xc3], [0x18], [0x96], [0x05], [0x9a],
        [0x07], [0x12], [0x80], [0xe2], [0xeb], [0x27], [0xb2], [0x75],
        [0x09], [0x83], [0x2c], [0x1a], [0x1b], [0x6e], [0x5a], [0xa0],
        [0x52], [0x3b], [0xd6], [0xb3], [0x29], [0xe3], [0x2f], [0x84],
        [0x53], [0xd1], [0x00], [0xed], [0x20], [0xfc], [0xb1], [0x5b],
        [0x6a], [0xcb], [0xbe], [0x39], [0x4a], [0x4c], [0x58], [0xcf],
        [0xd0], [0xef], [0xaa], [0xfb], [0x43], [0x4d], [0x33], [0x85],
        [0x45], [0xf9], [0x02], [0x7f], [0x50], [0x3c], [0x9f], [0xa8],
        [0x51], [0xa3], [0x40], [0x8f], [0x92], [0x9d], [0x38], [0xf5],
        [0xbc], [0xb6], [0xda], [0x21], [0x10], [0xff], [0xf3], [0xd2],
        [0xcd], [0x0c], [0x13], [0xec], [0x5f], [0x97], [0x44], [0x17],
        [0xc4], [0xa7], [0x7e], [0x3d], [0x64], [0x5d], [0x19], [0x73],
        [0x60], [0x81], [0x4f], [0xdc], [0x22], [0x2a], [0x90], [0x88],
        [0x46], [0xee], [0xb8], [0x14], [0xde], [0x5e], [0x0b], [0xdb],
        [0xe0], [0x32], [0x3a], [0x0a], [0x49], [0x06], [0x24], [0x5c],
        [0xc2], [0xd3], [0xac], [0x62], [0x91], [0x95], [0xe4], [0x79],
        [0xe7], [0xc8], [0x37], [0x6d], [0x8d], [0xd5], [0x4e], [0xa9],
        [0x6c], [0x56], [0xf4], [0xea], [0x65], [0x7a], [0xae], [0x08],
        [0xba], [0x78], [0x25], [0x2e], [0x1c], [0xa6], [0xb4], [0xc6],
        [0xe8], [0xdd], [0x74], [0x1f], [0x4b], [0xbd], [0x8b], [0x8a],
        [0x70], [0x3e], [0xb5], [0x66], [0x48], [0x03], [0xf6], [0x0e],
        [0x61], [0x35], [0x57], [0xb9], [0x86], [0xc1], [0x1d], [0x9e],
        [0xe1], [0xf8], [0x98], [0x11], [0x69], [0xd9], [0x8e], [0x94],
        [0x9b], [0x1e], [0x87], [0xe9], [0xce], [0x55], [0x28], [0xdf],
        [0x8c], [0xa1], [0x89], [0x0d], [0xbf], [0xe6], [0x42], [0x68],
        [0x41], [0x99], [0x2d], [0x0f], [0xb0], [0x54], [0xbb], [0x16]
    ];
    
    signal outs[wIn] <== Multiplexer(wIn,nIn)(substitutionBox,in);
    out <== outs[0];
}

/**
 * This is used in the AES key expansion algorithm where words
 * need to be processed through the S-Box transformation.
 */
template SubWord() {
    input Word() in;
    output Word() out;
    
    out.bytes <== SubstituteBytes(4)(in.bytes);
}

/**
 * The 16-byte state represents the 4x4 state matrix in column-major order.
 */
template SubBytes() {
    signal input {byte} in[16];
    signal output {byte} out[16];

    out <== SubstituteBytes(16)(in);
}

/**
 * Parameterized template that applies S-Box substitution to any number of bytes.
 * This provides flexibility for different use cases:
 * - byteCount = 4: for SubWord operations (key expansion)
 * - byteCount = 16: for SubBytes operations (main rounds)
 * 
 * @param byteCount Number of bytes to process through S-Box
 */
 template SubstituteBytes(byteCount) {
    signal input {byte} in[byteCount];
    signal output {byte} out[byteCount];
    
    for (var i = 0; i < byteCount; i++) {
        out[i] <== SBox()(in[i]);
    }
}

/**
 * The 16-byte state is stored in column-major order.
 */
template ShiftRows() {
    signal input {byte} in[16];
    signal output {byte} out[16];

    (out[0],out[4],out[8],out[12])  <== (in[0],in[4],in[8],in[12]);
    (out[1],out[5],out[9],out[13])  <== (in[5],in[9],in[13],in[1]);
    (out[2],out[6],out[10],out[14]) <== (in[10],in[14],in[2],in[6]);
    (out[3],out[7],out[11],out[15]) <== (in[15],in[3],in[7],in[11]);
}

/** 
 * Input:
 *   [s0, s1, s2, s3]
 *
 * Process:
 *   [2 3 1 1]   [s0,
 *   [1 2 3 1] * ,s1,
 *   [1 1 2 3]   ,s2,
 *   [3 1 1 2]   ,s3]
 *
 * Output:
 *   [2*s0 ⊕ 3*s1 ⊕ s2 ⊕ s3,
 *   ,s0 ⊕ 2*s1 ⊕ 3*s2 ⊕ s3,
 *   ,s0 ⊕ s1 ⊕ 2*s2 ⊕ 3*s3,
 *   ,3*s0 ⊕ s1 ⊕ s2 ⊕ 2*s3]
 * 
 * Where ⊕ represents XOR and multiplications are in GF(2^8).
 */
template MixColumn() {
    signal input {byte} in[4];
    signal output {byte} out[4];
    
    signal (s0_mul2, s0_mul3) <== (GF8Mul2()(in[0]), GF8Mul3()(in[0]));
    signal (s1_mul2, s1_mul3) <== (GF8Mul2()(in[1]), GF8Mul3()(in[1]));
    signal (s2_mul2, s2_mul3) <== (GF8Mul2()(in[2]), GF8Mul3()(in[2]));
    signal (s3_mul2, s3_mul3) <== (GF8Mul2()(in[3]), GF8Mul3()(in[3]));

    out[0] <== BitwiseXorOptimized(4, 8)([s0_mul2, s1_mul3, in[2], in[3]]);
    out[1] <== BitwiseXorOptimized(4, 8)([in[0], s1_mul2, s2_mul3, in[3]]);
    out[2] <== BitwiseXorOptimized(4, 8)([in[0], in[1], s2_mul2, s3_mul3]);
    out[3] <== BitwiseXorOptimized(4, 8)([s0_mul3, in[1], in[2], s3_mul2]);
}

/**
 * The 16-byte state is stored in column-major order.
 */
template MixColumns() {
    signal input {byte} in[16];
    signal output {byte} out[16];

    signal {byte} inCols[4][4];
    signal {byte} outCols[4][4];

    for (var c = 0; c < 4; c++) {
        for (var r = 0; r < 4; r++) {
            inCols[c][r] <== in[4 * c + r];
        }
        outCols[c] <== MixColumn()(inCols[c]);
        for (var r = 0; r < 4; r++) {
            out[4 * c + r] <== outCols[c][r];
        }
    }
}

template AddRoundKey() {
    signal input {byte} state[16];
    input Word() roundKey[4];
    signal output {byte} out[16];

    signal roundKeyBytes[16];
    for (var i = 0; i < 4; i++) {
        for (var j = 0; j < 4; j++) {
            roundKeyBytes[i * 4 + j] <== roundKey[i].bytes[j];
        }
    }
    
    for (var i = 0; i < 16; i++) {
        out[i] <== BitwiseXor(2,8)([state[i],roundKeyBytes[i]]);
    }
}

/**
 * AES Block Encryption Circuit
 * Implements the AES encryption algorithm for 128/192/256-bit keys
 * Following NIST FIPS 197 standard
 * 
 * @param keyBits - Key size in bits (128, 192, or 256)
 */
template EncryptBlock(keyBits) {
    var (Nk, Nr);
    assert(keyBits == 128 || keyBits == 192 || keyBits == 256);
    if (keyBits == 128) {
        (Nk, Nr) = (4, 10);
    } else if (keyBits == 192) {
        (Nk, Nr) = (6, 12);
    } else {
        (Nk, Nr) = (8, 14);
    }
    var expandedNk = 4 * (Nr + 1);
    
    signal input {byte} plaintext[16];
    input Word() key[Nk];
    signal output {byte} ciphertext[16];
    
    // Expand the key
    Word() roundKey[expandedNk] <== ExpandKey(keyBits)(key);

    // Group by 4 words for each round
    Word() roundKeyGroup[Nr + 1][4];
    for (var i = 0; i <= Nr; i++) {
        for (var j = 0; j < 4; j++) {
            roundKeyGroup[i][j] <== roundKey[4 * i + j];
        }
    }
    
    // State array to track transformations
    signal {byte} state[Nr][16];

    // Intermediate signals for each transformation step
    signal {byte} byteSubstituted[Nr][16];
    signal {byte} rowShifted[Nr][16];
    signal {byte} columnMixed[Nr - 1][16]; // No MixColumns in final round

    // Initial round - AddRoundKey only
    state[0] <== AddRoundKey()(plaintext, roundKeyGroup[0]);

    // Main rounds (1 to Nr-1): SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
    for (var round = 1; round <= Nr - 1; round++) {
        byteSubstituted[round - 1] <== SubBytes()(state[round - 1]);
        rowShifted[round - 1] <== ShiftRows()(byteSubstituted[round - 1]);
        columnMixed[round - 1] <== MixColumns()(rowShifted[round - 1]);
        state[round] <== AddRoundKey()(columnMixed[round - 1], roundKeyGroup[round]);
    }
    
    // Final round (no MixColumns)
    byteSubstituted[Nr - 1] <== SubBytes()(state[Nr - 1]);
    rowShifted[Nr - 1] <== ShiftRows()(byteSubstituted[Nr - 1]);
    ciphertext <== AddRoundKey()(rowShifted[Nr - 1], roundKeyGroup[Nr]);
}