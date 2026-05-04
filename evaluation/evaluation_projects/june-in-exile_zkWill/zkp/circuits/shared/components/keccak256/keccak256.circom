pragma circom 2.2.2;

include "sponge.circom";

/**
 * Complete Keccak256 Hash Function
 *
 * Combines padding, absorb, and squeeze phases
 * Generates 256-bit digest
 *
 * @param msgBits - Number of message bits
 */
template Keccak256(msgBits) {
    signal input {bit} msg[msgBits];
    signal output {bit} digest[256];

    var digestBits = 256;
    var rateBits = 1600 - 2 * digestBits;
    var numBlocks = ((msgBits + 2) - 1) \ rateBits + 1;
    var paddedMsgBits = numBlocks * rateBits;

    signal paddedMsg[paddedMsgBits] <== Padding(msgBits, rateBits)(msg);
    signal stateArray[5][5][64] <== Absorb(paddedMsgBits, rateBits)(paddedMsg);
    digest <== Squeeze(digestBits, rateBits)(stateArray);
}
