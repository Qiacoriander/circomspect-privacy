pragma circom 2.0.0;

include "./get_merkle_root.circom";

template LeafExistence(k) {
    // Checks for the existence of a leaf in a tree of depth k

    signal input leaf;
    signal input root;
    signal input path[k];
    signal input pathPositions[k];

    component computed_root = GetMerkleRoot(k);
    computed_root.leaf <== leaf;

    for (var w = 0; w < k; w++) {
        computed_root.path[w] <== path[w];
        computed_root.pathPositions[w] <== pathPositions[w];
    }

    // equality constraint: given tx root must be equal to computed one
    root === computed_root.out;
}