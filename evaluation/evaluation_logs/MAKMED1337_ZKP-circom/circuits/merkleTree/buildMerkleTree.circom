pragma circom 2.1.8;
include "incrementalMerkleTree.circom";

// Rewritten code from incrementalMerkleTree.circom:CheckRoot
template BuildMerkleTree(levels, index) {
    var totalLeaves = 2 ** levels;

    // The number of HashLeftRight components which will be used to hash the
    // leaves
    var numLeafHashers = totalLeaves / 2;

    // The number of HashLeftRight components which will be used to hash the
    // output of the leaf hasher components
    var numIntermediateHashers = numLeafHashers - 1;

    signal input leaves[totalLeaves];

    // signal output path[levels];
    // signal output proof[levels];
    signal output root;

    // The total number of hashers
    var numHashers = totalLeaves - 1;
    component hashers[numHashers];

    // Instantiate all hashers
    for (var i = 0; i < numHashers; i++) {
        hashers[i] = HashLeftRight();
    }

    // Wire the leaf values into the leaf hashers
    for (var i = 0; i < numLeafHashers; i++){
        hashers[i].left <== leaves[i*2];
        hashers[i].right <== leaves[i*2+1];
    }

    // Wire the outputs of the leaf hashers to the intermediate hasher inputs
    var k = 0, h = 0;
    for (var i=numLeafHashers; i<numLeafHashers + numIntermediateHashers; i++) {
        hashers[i].left <== hashers[k*2].hash;
        hashers[i].right <== hashers[k*2+1].hash;

        if (k*2 == index) {
            // proof[h] <== hashers[k*2+1].hash;
            // path[h] <== 0;
            index = i;
            h++;
        }
        if (k*2+1 == index) {
            // proof[h] <== hashers[k*2].hash;
            // path[h] <== 1;
            index = i;
            h++;
        }

        k++;
    }

    root <== hashers[numHashers - 1].hash;
}

component main = BuildMerkleTree(4, 5);

