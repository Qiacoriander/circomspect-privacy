pragma circom 2.2.2;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";
include "circomlib/circuits/mux2.circom";
include "bus.circom";

/**
 * UTF-8 Encoding Ranges:
 * - 1 byte:  U+0000   to U+007F    (0 to 127)              - ASCII characters
 * - 2 bytes: U+0080   to U+07FF    (128 to 2,047)          - Latin extended, Greek, Cyrillic, etc.
 * - 3 bytes: U+0800   to U+FFFF    (2,048 to 65,535)       - Most other scripts (CJK, etc.)
 * - 4 bytes: U+10000  to U+10FFFF  (65,536 to 1,114,111)   - Supplementary planes (emoji, etc.)
 * 
 * @param codepoint - Unicode codepoint (0 to 1,114,111)
 * @returns length[2] - 2-bit binary representation of byte length
 * 
 * Output Encoding:
 * - [0,0]: 1 byte  (length = 0*2 + 0 = 0, interpreted as 1)
 * - [1,0]: 2 bytes (length = 0*2 + 1 = 1, interpreted as 2)  
 * - [0,1]: 3 bytes (length = 1*2 + 0 = 2, interpreted as 3)
 * - [1,1]: 4 bytes (length = 1*2 + 1 = 3, interpreted as 4)
 * 
 * Examples:
 * - 'A' (65):      length = [0,0] (1 byte)
 * - 'ñ' (241):     length = [1,0] (2 bytes)
 * - '中' (20013):   length = [0,1] (3 bytes)
 * - '🚀' (128640):  length = [1,1] (4 bytes)
 */
template Utf8ByteLength() {
    signal input codepoint;
    signal output {bit} length[2];
    
    signal lt0x0080 <== LessThan(32)([codepoint,0x0080]);
    signal lt0x0800 <== LessThan(32)([codepoint,0x0800]);
    signal lt0x10000 <== LessThan(32)([codepoint,0x10000]);
    signal lt0x110000 <== LessThan(32)([codepoint,0x110000]);
    
    signal is1byte <== lt0x0080;
    signal is2byte <== (1 - lt0x0080) * lt0x0800;
    signal is3byte <== (1 - lt0x0800) * lt0x10000;
    signal is4byte <== (1 - lt0x10000) * lt0x110000;
    
    1 === is1byte + is2byte + is3byte + is4byte;
    
    length[0] <== is2byte + is4byte;
    length[1] <== is3byte + is4byte;
}

/**
 * Encoding Rules:
 * - 1 byte  (0-127):        0xxxxxxx
 * - 2 bytes (128-2047):     110xxxxx 10xxxxxx
 * - 3 bytes (2048-65535):   1110xxxx 10xxxxxx 10xxxxxx
 * - 4 bytes (65536+):       11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
 * 
 * @param codepoint - Unicode codepoint (0 to 1,114,111)
 * @returns bytes[4] - UTF-8 encoded bytes (unused bytes are set to 0)
 * @returns validBytes[4] - Binary flags indicating which bytes are valid
 * 
 * Examples:
 * - 'A' (U+0041 = 65):    bytes=[65,0,0,0],    validBytes=[1,0,0,0]
 * - 'ñ' (U+00F1 = 241):   bytes=[195,177,0,0], validBytes=[1,1,0,0]
 * - '中' (U+4E2D = 20013): bytes=[228,184,173,0], validBytes=[1,1,1,0]
 * - '🚀' (U+1F680 = 128640): bytes=[240,159,154,128], validBytes=[1,1,1,1]
 */
template Utf8Encoder() {
    signal input codepoint;
    output Utf8() utf8;
    
    signal codepointBits[21] <== Num2Bits(21)(codepoint);  // Unicode requires 21-bit at most
    
    // 1-byte encoding (0xxxxxxx)
    signal byte1_1byte <== Bits2Num(8)([codepointBits[0],codepointBits[1],codepointBits[2],codepointBits[3],codepointBits[4],codepointBits[5],codepointBits[6],0]);
    
    // 2-byte encoding (110xxxxx 10xxxxxx)
    // 11000000 | (codepoint >> 6)
    signal byte1_2byte <== Bits2Num(8)([codepointBits[6],codepointBits[7],codepointBits[8],codepointBits[9],codepointBits[10],0,1,1]);
    // 10000000 | (codepoint & 00111111)
    signal byte2_2byte <== Bits2Num(8)([codepointBits[0],codepointBits[1],codepointBits[2],codepointBits[3],codepointBits[4],codepointBits[5],0,1]);
    
    // 3-byte encoding (1110xxxx 10xxxxxx 10xxxxxx)
    // 11100000 | (codepoint >> 12)
    signal byte1_3byte <== Bits2Num(8)([codepointBits[12],codepointBits[13],codepointBits[14],codepointBits[15],0,1,1,1]);
    // 10000000 | ((codepoint >> 6) & 00111111)
    signal byte2_3byte <== Bits2Num(8)([codepointBits[6],codepointBits[7],codepointBits[8],codepointBits[9],codepointBits[10],codepointBits[11],0,1]);
    // 10000000 | (codepoint & 00111111)
    signal byte3_3byte <== Bits2Num(8)([codepointBits[0],codepointBits[1],codepointBits[2],codepointBits[3],codepointBits[4],codepointBits[5],0,1]);
    
    // 4-byte encoding (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
    // 11110000 | (codepoint >> 18)
    signal byte1_4byte <== Bits2Num(8)([codepointBits[18],codepointBits[19],codepointBits[20],0,1,1,1,1]);
    // 10000000 | ((codepoint >> 12) & 00111111)
    signal byte2_4byte <== Bits2Num(8)([codepointBits[12],codepointBits[13],codepointBits[14],codepointBits[15],codepointBits[16],codepointBits[17],0,1]);
    // 10000000 | ((codepoint >> 6) & 00111111)
    signal byte3_4byte <== Bits2Num(8)([codepointBits[6],codepointBits[7],codepointBits[8],codepointBits[9],codepointBits[10],codepointBits[11],0,1]);
    // 10000000 | (codepoint & 00111111)
    signal byte4_4byte <== Bits2Num(8)([codepointBits[0],codepointBits[1],codepointBits[2],codepointBits[3],codepointBits[4],codepointBits[5],0,1]);
    
    signal {bit} length[2] <== Utf8ByteLength()(codepoint);

    utf8.bytes[0] <== Mux2()([byte1_1byte,byte1_2byte,byte1_3byte,byte1_4byte],length);
    utf8.bytes[1] <== Mux2()([0,byte2_2byte,byte2_3byte,byte2_4byte],length);
    utf8.bytes[2] <== Mux2()([0,0,byte3_3byte,byte3_4byte],length);
    utf8.bytes[3] <== Mux2()([0,0,0,byte4_4byte],length);
    
    utf8.validBytes[0] <== 1;
    utf8.validBytes[1] <== OR()(length[0],length[1]);
    utf8.validBytes[2] <== IsEqual()([length[1],1]);
    utf8.validBytes[3] <== AND()(length[0],length[1]);
}

/**
 * @param length - Fixed number of characters to encode
 * 
 * Input:
 * - codepoints[length] - Array of Unicode codepoints to encode
 * 
 * Output: 
 * - bytes[length * 4] - Packed UTF-8 byte sequence (max 4 bytes per char)
 * - validByteCount - Total number of valid bytes in the output
 * 
 * Example:
 * Input:  codepoints = [65, 20013, 128640]  // "A中🚀"
 * Output: bytes = [65, 228, 184, 173, 240, 159, 154, 128, 0, 0, 0, 0]
 *         validByteCount = 8
 */
template Utf8StringEncoder(length) {
    signal input codepoints[length];
    signal output bytes[length * 4];
    signal output validByteCount;
    
    // ========== CHARACTER ENCODING ==========
    Utf8() utf8s[length];
    for (var i = 0; i < length; i++) {
        utf8s[i] <== Utf8Encoder()(codepoints[i]);
    }

    // ========== VALID BYTE CALCULATION ==========
    signal cumulativeByteCounts[length];
    cumulativeByteCounts[0] <== utf8s[0].validBytes[0] + utf8s[0].validBytes[1] + utf8s[0].validBytes[2] + utf8s[0].validBytes[3];
    for (var i = 1; i < length; i++) {
        cumulativeByteCounts[i] <== cumulativeByteCounts[i-1] + utf8s[i].validBytes[0] + utf8s[i].validBytes[1] + utf8s[i].validBytes[2] + utf8s[i].validBytes[3];
    }
    validByteCount <== cumulativeByteCounts[length-1];

    // ========== BYTE PACKING ==========
    // e.g., [65, 0, 0, 0, 228, 184, 173, 0, 240, 159, 154, 128] -> [65, 228, 184, 173, 240, 159, 154, 128, 0, 0, 0, 0]
    signal firstByteOfChar[length]; // Decide the starting byte offset for each character
    firstByteOfChar[0] <== 0;
    for (var i = 1; i < length; i++) {
        firstByteOfChar[i] <== cumulativeByteCounts[i-1];
    }
    
    // For each output byte position, determine which character byte it should contain
    signal posMatched[length * 4][length][4];
    signal selected[length * 4][length][4];
    signal selectedBytes[length * 4][length][4];
    signal characterContributions[length * 4][length];
    signal tempSum[length * 4][length];
    
    for (var outPos = 0; outPos < length * 4; outPos++) {
        for (var charIdx = 0; charIdx < length; charIdx++) {
            for (var byteIdx = 0; byteIdx < 4; byteIdx++) {
                // Check if this output position matches this character's byte position
                posMatched[outPos][charIdx][byteIdx] <== IsEqual()([firstByteOfChar[charIdx] + byteIdx,outPos]);
                
                // Select the byte if position matches and byte is valid
                selected[outPos][charIdx][byteIdx] <== posMatched[outPos][charIdx][byteIdx] * utf8s[charIdx].validBytes[byteIdx];

                // Put the byte into the output position only if it is selected
                selectedBytes[outPos][charIdx][byteIdx] <== selected[outPos][charIdx][byteIdx] * utf8s[charIdx].bytes[byteIdx];
            }
            
            // Sum all byte contributions from this character for this output position
            characterContributions[outPos][charIdx] <== 
                selectedBytes[outPos][charIdx][0] + 
                selectedBytes[outPos][charIdx][1] + 
                selectedBytes[outPos][charIdx][2] + 
                selectedBytes[outPos][charIdx][3];
        }
        
        // Sum contributions from all characters for this output position
        tempSum[outPos][0] <== characterContributions[outPos][0];
        
        for (var charIdx = 1; charIdx < length; charIdx++) {
            tempSum[outPos][charIdx] <== tempSum[outPos][charIdx-1] + characterContributions[outPos][charIdx];
        }
        
        // Final byte value for this position
        bytes[outPos] <== tempSum[outPos][length-1];
    }
}