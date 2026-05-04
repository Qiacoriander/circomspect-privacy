pragma circom 2.2.2;

/*
 * A simplified version of abi.encode() in solidity
 *
 * @param numValues - Number of values to encode, each takes 32 bytes
 */
template AbiEncode(numValues) {
    var numOutBytes = numValues * 32;
    signal input {byte} values[numValues][32];
    signal output {byte} encodedValue[numOutBytes];

    for (var i = 0; i < numValues; i++) {
        for (var j = 0; j < 32; j++) {
            encodedValue[i * 32 + j] <== values[i][j];
        }
    }
}