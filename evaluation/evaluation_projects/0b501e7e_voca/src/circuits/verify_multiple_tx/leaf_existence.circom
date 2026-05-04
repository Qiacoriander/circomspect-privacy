pragma circom 2.0.0;

include "./get_merkle_root.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

// checks for existence of leaf in tree of depth k

template LeafExistence(k){
    // k is depth of tree
    // l is depth of preimage of leaf
    
    signal input leafNode;
    signal input root;
    signal input siblingHashes[k];
    signal input siblingPositions[k];


    component computed_root = GetMerkleRoot(k);
    computed_root.leafNode <== leafNode;

    for (var w = 0; w < k; w++){
        computed_root.siblingHashes[w] <== siblingHashes[w];
        computed_root.siblingPositions[w] <== siblingPositions[w];
    }

    root === computed_root.merkleRoot;
}

// component main {public [leaf, root, siblingHashes, siblingPositions]} = LeafExistence(2);