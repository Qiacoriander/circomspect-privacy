pragma circom 2.0.0;

include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../node_modules/circomlib/circuits/switcher.circom";

// Computes the hash that represents the account leaf in the balance tree
template SlidingCongestionAccountLeaf(nTiers) {
    signal input X;  // x component of the public key
    signal input Y;  // y component of the public key
    signal input balance;
    signal input nonce;
    signal input currentPlan;
    signal input txTimestamps[16*nTiers];

    signal output out;

    component txTimestampsTree = Poseidon(nTiers);
    component txTimestampsBranches[nTiers];
    component comparators[nTiers];
    component selectors[nTiers];

    for (var i = 0; i < nTiers; i++) {
        txTimestampsBranches[i] = Poseidon(16);

        for (var j = 0; j < 16; j++) {
            txTimestampsBranches[i].inputs[j] <== txTimestamps[16*i + j];
        }

        comparators[i] = GreaterEqThan(5);
        comparators[i].in[0] <== currentPlan;
        comparators[i].in[1] <== nTiers - i;

        selectors[i] = Switcher();
        selectors[i].L <== txTimestampsBranches[i].out;
        selectors[i].R <== 0; 
        selectors[i].sel <== comparators[i].out;

        txTimestampsTree.inputs[i] <== selectors[i].outR;
    }

    component accountLeaf = Poseidon(6);
    accountLeaf.inputs[0] <== X;
    accountLeaf.inputs[1] <== Y;
    accountLeaf.inputs[2] <== balance;
    accountLeaf.inputs[3] <== nonce;
    accountLeaf.inputs[4] <== currentPlan;
    accountLeaf.inputs[5] <== txTimestampsTree.out;

    out <== accountLeaf.out;
}

template ReducedSlidingCongestionAccountLeaf() {
    signal input X;  // x component of the public key
    signal input Y;  // y component of the public key
    signal input balance;
    signal input nonce;
    signal input currentPlan;
    signal input txTimestampsRoot;

    signal output out;

    component reducedAccountLeaf = Poseidon(6);
    reducedAccountLeaf.inputs[0] <== X;
    reducedAccountLeaf.inputs[1] <== Y;
    reducedAccountLeaf.inputs[2] <== balance;
    reducedAccountLeaf.inputs[3] <== nonce;
    reducedAccountLeaf.inputs[4] <== currentPlan;
    reducedAccountLeaf.inputs[5] <== txTimestampsRoot;

    out <== reducedAccountLeaf.out;
}
