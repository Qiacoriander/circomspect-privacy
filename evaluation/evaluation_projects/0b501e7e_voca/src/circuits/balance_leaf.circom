pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/poseidon.circom";

template BalanceLeaf() {
    // Computes the hash that represents the account leaf in the balance tree

    signal input x;  // x component of the public key
    signal input y;  // y component of the public key
    signal input tokenBalance;
    signal input nonce;
    signal input tokenType;

    signal output out;

    component balanceLeaf = Poseidon(5);
    balanceLeaf.inputs[0] <== x;
    balanceLeaf.inputs[1] <== y;
    balanceLeaf.inputs[2] <== tokenBalance;
    balanceLeaf.inputs[3] <== nonce;
    balanceLeaf.inputs[4] <== tokenType;

    out <== balanceLeaf.out;
}