pragma circom 2.0.0;

include "./get_merkle_root.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

// checks for existence of leaf in tree of depth k

template LeafExistence(k, l){
    // k is depth of tree
    // l is depth of preimage of leaf
    
    signal input preimage[l];
    signal input root;
    signal input siblingHashes[k];
    signal input siblingPositions[k];

    component leaf = Poseidon(l);
    for (var i = 0; i < l; i++) {
        leaf.inputs[i] <== preimage[i];
    }

    component computed_root = GetMerkleRoot(k);
    computed_root.leafNode <== leaf.out;

    for (var w = 0; w < k; w++){
        computed_root.siblingHashes[w] <== siblingHashes[w];
        computed_root.siblingPositions[w] <== siblingPositions[w];
    }

    root === computed_root.merkleRoot;
}

// component main {public [leaf, root, siblingHashes, siblingPositions]} = LeafExistence(2);