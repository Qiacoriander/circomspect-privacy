pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/switcher.circom";




template MerkleTreeChecker(levels) {
    signal input leaf;
    signal input root;
    signal input pathElements[levels];
    signal input insertedIndex;

    
    component pathIndices = Num2Bits(levels);
    pathIndices.in <== insertedIndex;

    component switchers[levels];
    component hashers[levels];

    var levelHash;
    levelHash = leaf;

    for (var i = 0; i < levels; i++) {
        switchers[i] = Switcher();
        switchers[i].L <== levelHash;
        switchers[i].R <== pathElements[i];
        switchers[i].sel <== pathIndices.out[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        levelHash = hashers[i].out;
    }

    root === levelHash;
}