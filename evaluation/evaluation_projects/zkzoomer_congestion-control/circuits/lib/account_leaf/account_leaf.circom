pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/poseidon.circom";

// Computes the hash that represents the account leaf in the accounts tree
template AccountLeaf() {
    signal input X;  // x component of the public key
    signal input Y;  // y component of the public key
    signal input balance;
    signal input nonce;

    signal output out;

    component accountLeaf = Poseidon(4);
    accountLeaf.inputs[0] <== X;
    accountLeaf.inputs[1] <== Y;
    accountLeaf.inputs[2] <== balance;
    accountLeaf.inputs[3] <== nonce;

    out <== accountLeaf.out;
}
