pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/switcher.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/mimc.circom";

// Hash left and right inputs using Poseidon.
// template HashLR() {
//     signal input L;
//     signal input R;
//     signal output out;

//     component hasher = Poseidon(2);
//     hasher.inputs[0] <== L;
//     hasher.inputs[1] <== R;

//     hasher.out ==> out;
// }

// template HashSingle() {
//     signal input single;
//     signal output out;

//     component hasher = Poseidon(1);
//     hasher.inputs[0] <== single;

//     hasher.out ==> out;
// }

// Hash using MiMC7.
template HashLR() {
    signal input L;
    signal input R;
    signal output out;

    // Define a MiMC7 hash circuit with 2 inputs and 91 rounds
    component hasher = MultiMiMC7(2, 91);
    hasher.in[0] <== L;
    hasher.in[1] <== R;
    // Give hasher a fixed key of 1.
    hasher.k <== 1;
    out <== hasher.out;
}

template HashSingle() {
    signal input single;
    signal output out;

    // Define a MiMC7 hash circuit with 2 inputs and 91 rounds
    component hasher = MiMC7(91);
    hasher.x_in <== single;
    // Give hasher a fixed key of 1.
    hasher.k <== 1;
    out <== hasher.out;
}

/***************************************************************************************************
                                            ?ABCDEFG
                                            /      \
                                        ?ABC       DEFG
                                        /   \      /   \
                                      ?A    BC    DE   FG
                                     / \   / \   / \  / \
                                    ?  A  B  C  D  E F  G
***************************************************************************************************/
// TREE_CAPACITY must be a power of 2.
template VedaMerkleTree(TREE_CAPACITY) {
    var layerIterations = 0;
    for (var i=0; 1 != TREE_CAPACITY / (2 ** i); i++) {
        layerIterations++;
    }
    var arrayLength = 0;
    for (var i=0; i<layerIterations; i++) {
        arrayLength += TREE_CAPACITY / 2 ** (i + 1);
    }

    // Public signals.
    signal output rootWithSecret;
    signal output rootWithNull;
    signal output secretLeafHash; // Stored by contract to revert if verification is tried with secret leaf.

    // Private signals.
    // Minus 1 since one leaf is reserved for the secret leaf.
    signal input leafsInTwo[TREE_CAPACITY - 1][2]; // leafs broken into 2 signals so that keccak256 hashes can be used.
    signal input secretLeaf; // Secret leaf to be added to the tree
    signal input pathIndices[arrayLength];

    // Internal signals.
    // Minus 1 since one leaf is reserved for the secret leaf.
    signal leafs[TREE_CAPACITY - 1];
    signal nullLeaf <== 0;

    // Components.
    component hashersWithNull[arrayLength + TREE_CAPACITY - 1];
    component hashersWithSecret[layerIterations];
    component switchersWithNull[arrayLength];
    component switchersWithSecret[layerIterations];
    component secretLeafHashser = HashSingle();

    // Hash the secret leaf.
    secretLeafHashser.single <== secretLeaf;
    secretLeafHash <== secretLeafHashser.out;

    // The tree with null and tree with secret will share the majority of the same hashes, with the exception being the
    // first hash of every layer

    // Ingest leafsInTwo into leafs using Poseidon(leafsInTwo[0], leafsInTwo[1]) -> leafs.
    for (var i=0; i<TREE_CAPACITY - 1; i++) {
        hashersWithNull[i] = HashLR();
        hashersWithNull[i].L <== leafsInTwo[i][0];
        hashersWithNull[i].R <== leafsInTwo[i][1];
        leafs[i] <== hashersWithNull[i].out;
    }

    // Hash the first layer of leafs.
    // As for a tree of 8 leafs, with one secret leaf, the majority of hashes between the secret and no secret tree are the same.
    var hashersIndex = 0;
    var hasherOffset = TREE_CAPACITY - 1;
    var switcherOffset = 0;
    for (var i=0; i<layerIterations; i++) {
        // Start with Null tree.
        // Set up switcher.
        switchersWithNull[switcherOffset] = Switcher();
        switchersWithNull[switcherOffset].L <== i == 0 ? nullLeaf : hashersWithNull[hashersIndex].out;
        switchersWithNull[switcherOffset].R <== i == 0 ? hashersWithNull[hashersIndex].out : hashersWithNull[hashersIndex + 1].out;
        switchersWithNull[switcherOffset].sel <== pathIndices[switcherOffset];
        
        // Setup hasher.
        hashersWithNull[hasherOffset] = HashLR();
        hashersWithNull[hasherOffset].L <== switchersWithNull[switcherOffset].outL;
        hashersWithNull[hasherOffset].R <== switchersWithNull[switcherOffset].outR;

        // Now do the Secret tree.
        // Set up switcher.
        // Since we know these components are used for the first hash of each layer, we do not need to use offset logic, instead we can just use i.
        // Note we use the same path indices so that both trees use the same indices for the firt element of each layer.
        switchersWithSecret[i] = Switcher();
        switchersWithSecret[i].L <== i == 0 ? secretLeaf : hashersWithSecret[i-1].out;
        switchersWithSecret[i].R <== i == 0 ? hashersWithNull[hashersIndex].out : hashersWithNull[hashersIndex + 1].out;
        switchersWithSecret[i].sel <== pathIndices[switcherOffset];

        // Setup hasher.
        hashersWithSecret[i] = HashLR();
        hashersWithSecret[i].L <== switchersWithSecret[i].outL;
        hashersWithSecret[i].R <== switchersWithSecret[i].outR;

        // Only increment by 1 if on the initial layer since we only used the output from 1 hasher.
        hashersIndex += i == 0 ? 1 : 2;

        // Now iterate through the rest of the layer.
        var iterations = TREE_CAPACITY / (2 ** (i + 1));
        for (var j=1; j<iterations; j++) {
            // Setup switcher.
            switchersWithNull[j + switcherOffset] = Switcher();
            switchersWithNull[j + switcherOffset].L <== hashersWithNull[hashersIndex].out;
            switchersWithNull[j + switcherOffset].R <== hashersWithNull[hashersIndex + 1].out;
            switchersWithNull[j + switcherOffset].sel <== pathIndices[j + switcherOffset];

            // Setup hasher.
            hashersWithNull[j + hasherOffset] = HashLR();
            hashersWithNull[j + hasherOffset].L <== switchersWithNull[j + switcherOffset].outL;
            hashersWithNull[j + hasherOffset].R <== switchersWithNull[j + switcherOffset].outR;

            hashersIndex += 2;
        }
        hasherOffset += iterations;
        switcherOffset += iterations;
    }

    // Constrain final root hashes.
    rootWithNull <== hashersWithNull[hasherOffset - 1].out;
    rootWithSecret <== hashersWithSecret[layerIterations - 1].out;
}

component main = VedaMerkleTree(1024);