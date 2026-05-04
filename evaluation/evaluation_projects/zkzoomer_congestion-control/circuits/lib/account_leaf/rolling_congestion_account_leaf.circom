pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/poseidon.circom";

// Computes the hash that represents the account leaf in the balance tree
template RollingCongestionAccountLeaf() {
    signal input X;  // x component of the public key
    signal input Y;  // y component of the public key
    signal input balance;
    signal input nonce;
    signal input currentPlan;
    signal input lastOnline;
    signal input nTransactions;

    signal output out;

    component accountLeaf = Poseidon(7);
    accountLeaf.inputs[0] <== X;
    accountLeaf.inputs[1] <== Y;
    accountLeaf.inputs[2] <== balance;
    accountLeaf.inputs[3] <== nonce;
    accountLeaf.inputs[4] <== currentPlan;
    accountLeaf.inputs[5] <== lastOnline;
    accountLeaf.inputs[6] <== nTransactions;

    out <== accountLeaf.out;
}
