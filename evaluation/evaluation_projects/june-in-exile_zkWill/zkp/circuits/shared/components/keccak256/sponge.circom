pragma circom 2.2.2;

include "circomlib/circuits/gates.circom";
include "keccakF1600.circom";
include "../bits.circom";

/**
 * Keccak Padding (10*1 pattern)
 *
 * Adds padding to message to make it a multiple of rate bits
 * 
 * @param msgBits - Message length in bits
 * @param rateBits - Rate (i.e., block size) in bits (1088 for Keccak256)
 */
template Padding(msgBits, rateBits) {
    var numBlocks = ((msgBits + 2) - 1) \ rateBits + 1;
    var paddedMsgBits = numBlocks * rateBits;

    signal input {bit} msg[msgBits];
    signal output {bit} paddedMsg[paddedMsgBits];
    
    // Copy the original bit
    for (var i = 0; i < msgBits; i++) {
        paddedMsg[i] <== msg[i];
    }

    // First and last padding bit is 1
    paddedMsg[msgBits] <== 1;
    paddedMsg[paddedMsgBits - 1] <== 1;
    // Fill middle padding bits with 0
    for (var i = msgBits + 1; i < paddedMsgBits - 1; i++) {
        paddedMsg[i] <== 0;
    }
}

/**
 * Keccak Absorb Phase
 *
 * Processes padded input in rate-sized blocks
 * XOR each states with block and apply Keccak-f[1600] permutation
 * 
 * @param msgBits - Message length in bits (including padding)
 * @param rateBits - Rate in bits (1088 for Keccak256)
 */
template Absorb(msgBits, rateBits) {
    assert(msgBits > 0);
    assert(msgBits % rateBits == 0);
    var numBlocks = msgBits \ rateBits;
    
    signal input {bit} msg[msgBits];
    signal output {bit} finalStateArray[5][5][64];
    
    signal blocks[numBlocks][rateBits];
    signal {bit} statesArray[numBlocks + 1][5][5][64];
    signal {bit} xoredStatesArray[numBlocks][5][5][64];

    // Convert message into blocks
    for (var blockIdx = 0; blockIdx < numBlocks; blockIdx++) {
        for (var bitIdx = 0; bitIdx < rateBits; bitIdx++) {
            blocks[blockIdx][bitIdx] <== msg[blockIdx * rateBits + bitIdx];
        }
    }

    // Initial the first state
    for (var x = 0; x < 5; x++) {
        for (var y = 0; y < 5; y++) {
            for (var z = 0; z < 64; z++) {
                statesArray[0][x][y][z] <== 0;
            }
        }
    }
    
    var effectiveNumLanes = rateBits \ 64;
    for (var blockIdx = 0; blockIdx < numBlocks; blockIdx++) {
        for (var y = 0; y < 5; y++) {
            for (var x = 0; x < 5; x++) {
                var laneIdx = 5 * y + x;
                if (laneIdx < effectiveNumLanes) {
                    // Xor state bit with current block bit
                    for (var z = 0; z < 64; z++) {
                        var bitIdx = 64 * laneIdx + z;
                        xoredStatesArray[blockIdx][x][y][z] <== XOR()(statesArray[blockIdx][x][y][z], blocks[blockIdx][bitIdx]);
                    }
                } else {
                    // Copy the previous state
                    xoredStatesArray[blockIdx][x][y] <== statesArray[blockIdx][x][y];
                }
            }
        }
        
        // Apply Keccak-f[1600] permutation
        statesArray[blockIdx + 1] <== KeccakF1600()(xoredStatesArray[blockIdx]);
    }
    
    finalStateArray <== statesArray[numBlocks];
}

/**
 * Keccak Squeeze Phase
 *
 * Extracts digest bits from the final state
 * Applies Keccak-f[1600] permutation to generate enough digest bits
 * 
 * @param digestBits - Number of digest bits (256 for Keccak256)
 * @param rateBits - Rate in bits (1088 for Keccak256)
 */
template Squeeze(digestBits, rateBits) {
    var numBlocks = ((digestBits - 1) \ rateBits) + 1;

    signal input {bit} stateArray[5][5][64];
    signal output {bit} digest[digestBits];

    signal {bit} statesArray[numBlocks][5][5][64];
    var effectiveNumLanes = rateBits \ 64;

    for (var blockIdx = 0; blockIdx < numBlocks; blockIdx++) {
        if (blockIdx == 0) {
            // Initialize the first state
            statesArray[0] <== stateArray;
        } else {
            // Calculate the next block
            statesArray[blockIdx] <== KeccakF1600()(statesArray[blockIdx - 1]);
        }
        // Extract digest from the first 17 lanes of each state
        for (var y = 0; y < 5; y++) {
            for (var x = 0; x < 5; x++) {
                var laneIdx = x + 5 * y;
                if (laneIdx < effectiveNumLanes) {
                    for (var z = 0; z < 64; z++) {
                        var bitIdx = laneIdx * 64 + z;
                        var digestIdx = blockIdx * rateBits + bitIdx;
                        if (digestIdx < digestBits) {
                            digest[digestIdx] <== statesArray[blockIdx][x][y][z];
                        }
                    }
                }
            }
        }
    }
}