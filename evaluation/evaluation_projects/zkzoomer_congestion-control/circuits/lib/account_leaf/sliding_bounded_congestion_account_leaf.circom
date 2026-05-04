pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/poseidon.circom";

// Computes the hash that represents the account leaf in the balance tree
template SlidingBoundedCongestionAccountLeaf() {
    signal input X;  // x component of the public key
    signal input Y;  // y component of the public key
    signal input balance;
    signal input nonce;
    signal input currentPlan[2];
    signal input lastOnline;
    signal input credit;

    signal output out;

    component accountLeaf = Poseidon(8);
    accountLeaf.inputs[0] <== X;
    accountLeaf.inputs[1] <== Y;
    accountLeaf.inputs[2] <== balance;
    accountLeaf.inputs[3] <== nonce;
    accountLeaf.inputs[4] <== currentPlan[0];  // alpha
    accountLeaf.inputs[5] <== currentPlan[1];  // beta
    accountLeaf.inputs[6] <== lastOnline;
    accountLeaf.inputs[7] <== credit;

    out <== accountLeaf.out;
}
