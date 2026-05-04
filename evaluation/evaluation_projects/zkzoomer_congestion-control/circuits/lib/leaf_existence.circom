pragma circom 2.0.0;

include "./get_merkle_root.circom";

// Checks for the existence of a leaf in a tree of depth k
template LeafExistence(k) {
    signal input leaf;
    signal input treeSiblings[k];
    signal input treePathIndices[k];

    signal output out;

    component computedRoot = GetMerkleRoot(k);
    computedRoot.leaf <== leaf;

    for (var i = 0; i < k; i++) {
        computedRoot.treeSiblings[i] <== treeSiblings[i];
        computedRoot.treePathIndices[i] <== treePathIndices[i];
    }

    // equality constraint: given tx root must be equal to computed one
    out <== computedRoot.out;
}
