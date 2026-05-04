pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/poseidon.circom";

// Computes the hash that represents the account leaf in the accounts tree
template InitialCongestionAccountLeaf() {
    signal input X;  
    signal input Y;
    signal input balance;
    signal input nonce;
    signal input lastOnline;

    signal output out;

    component accountLeaf = Poseidon(5);
    accountLeaf.inputs[0] <== X;
    accountLeaf.inputs[1] <== Y;
    accountLeaf.inputs[2] <== balance;
    accountLeaf.inputs[3] <== nonce;
    accountLeaf.inputs[4] <== lastOnline;

    out <== accountLeaf.out;
}
