pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/mimc.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "QuinSelector.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template HashLeftRight() {
    signal input left;
    signal input right;
    signal output out;

    // Define a MiMC7 hash circuit with 2 inputs and 91 rounds
    component hasher = MultiMiMC7(2, 91);
    hasher.in[0] <== left;
    hasher.in[1] <== right;
    // Give hasher a fixed key of 1.
    hasher.k <== 1;
    out <== hasher.out;
}

template DualMux() {
    signal input in[2];
    signal input s;
    signal output out[2];

    // Constrain s to 0 or 1
    s * (1 - s) === 0;
    // Order in[0] and in[1] based on s
    // s == 0 => out[0] == in[0] and out[1] == in[1]
    // s == 1 => out[0] == in[1] and out[1] == in[0]
    out[0] <== (in[1] - in[0]) * s + in[0];
    out[1] <== (in[0] - in[1]) * s + in[1];
}

// TODO so even with just 2 leafs, pathIndices is still length 1, which it is actually never used. not a deal breaker since everything else works though.
template ShuffledMerkleTree(LEAF_COUNT) {
    signal input keccakLeafs[2 * LEAF_COUNT];
    signal output shuffledRoot;
    signal input leafIndices[LEAF_COUNT];
    // Determine array length.
    var arrayLength = 0;
    for (var i=0; 1 != LEAF_COUNT / (2 ** i); i++) {
        arrayLength += LEAF_COUNT / 2 ** (i + 1);
    }
    signal input pathIndices[arrayLength]; // Do not need pathIndices for the root.

    // Verify all indexes are used.
    component eqs[LEAF_COUNT][LEAF_COUNT];
    component calcTotal[LEAF_COUNT];
    for (var i = 0; i< LEAF_COUNT; i++) {
        calcTotal[i] = CalculateTotal(LEAF_COUNT);
        for (var j = 0; j< LEAF_COUNT; j++) {
            eqs[i][j] = IsEqual();
            eqs[i][j].in[0] <== i; // We check that i in an index in the leafIndices array to prevent repeat leafs.
            eqs[i][j].in[1] <== leafIndices[j];
            calcTotal[i].in[j] <== eqs[i][j].out;
        }
        calcTotal[i].out === 1;
    }

    // Internal signals.
    signal leafs[LEAF_COUNT];

    // Components.
    component keccakLeafHashers[LEAF_COUNT];
    component quinSelectors[LEAF_COUNT];
    component selectors[arrayLength - (LEAF_COUNT/2)];
    component hashers[arrayLength]; // Add LEAF_COUNT to pre-hash every leaf with the secret.


    // Hash keccakLeafs into leafs.
    for (var i=0; i<LEAF_COUNT; i++) {
        keccakLeafHashers[i] = HashLeftRight();
        keccakLeafHashers[i].left <== keccakLeafs[i * 2];
        keccakLeafHashers[i].right <== keccakLeafs[i * 2 + 1];
        leafs[i] <== keccakLeafHashers[i].out;
    }

    // Hash leaf layer.
    // Note no selectors are used because leafs are hashed in order of the leafIndices.
    for (var i=0; i<LEAF_COUNT/2; i++) {
        quinSelectors[2 * i] = QuinSelector(LEAF_COUNT);
        for (var j=0; j<LEAF_COUNT; j++) {
            quinSelectors[2 * i].in[j] <== leafs[j];
        }
        quinSelectors[2 * i].index <== leafIndices[2 * i];
        quinSelectors[2 * i + 1] = QuinSelector(LEAF_COUNT);
        for (var j=0; j<LEAF_COUNT; j++) {
            quinSelectors[2 * i + 1].in[j] <== leafs[j];
        }
        quinSelectors[2 * i + 1].index <== leafIndices[2 * i + 1];

        hashers[i] = HashLeftRight();
        hashers[i].left <== quinSelectors[2 * i].out;
        hashers[i].right <== quinSelectors[2 * i + 1].out;
    }

    var hasherOffset = LEAF_COUNT / 2;
    var hasherIndex = 0;
    var selectorOffset = 0;
    // Hash internal digests
    for (var i=1; 1 != LEAF_COUNT / (2 ** i); i++) {
        var iterations = LEAF_COUNT / (2 ** (i + 1));
        for (var j=0; j<iterations; j++) {
            selectors[j + selectorOffset] = DualMux();
            selectors[j + selectorOffset].in[0] <== hashers[hasherIndex].out;
            selectors[j + selectorOffset].in[1] <== hashers[hasherIndex + 1].out;
            selectors[j + selectorOffset].s <== pathIndices[j + selectorOffset];

            hashers[j + hasherOffset] = HashLeftRight();
            hashers[j + hasherOffset].left <== selectors[j + selectorOffset].out[0];
            hashers[j + hasherOffset].right <== selectors[j + selectorOffset].out[1];

            hasherIndex += 2;
        }
        hasherOffset += iterations;
        selectorOffset += iterations;
    }

    shuffledRoot <== hashers[hasherOffset - 1].out;
}

component main {public [keccakLeafs]} = ShuffledMerkleTree(2);