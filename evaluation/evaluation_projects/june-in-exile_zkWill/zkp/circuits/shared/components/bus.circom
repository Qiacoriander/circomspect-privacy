pragma circom 2.2.2;

bus Utf8() {
    signal {byte} bytes[4];
    signal {bit} validBytes[4];
}

bus Word() {
    signal {byte} bytes[4];
}

bus Estate() {
    signal {address} beneficiary;
    signal {address} token;
    signal amount;
}

/*
 * uint256 is composed of 4 64-bit registers, little-endian
 */
bus EcdsaPoint() {
    signal {uint64} x[4];
    signal {uint64} y[4];
}

/*
 * uint256 is composed of 4 64-bit registers, little-endian
 */
bus EcdsaSignature() {
    signal {uint64} r[4];
    signal {uint64} s[4];
    signal {byte} v;    
}

bus TokenPermission() {
    signal {address} token;
    signal amount;
}

bus PermitBatchTransferFrom(numPermission) {
    TokenPermission() permitted[numPermission];
    signal {uint128} nonce;
    signal {uint32} deadline;
}