pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/eddsaposeidon.circom";
include "./node_modules/circomlib/circuits/poseidon.circom";

template GetMerkleRoot(k) {
    // Gets the root of a given Merkle tree, where k is its depth

    // The root is achieved by hashing a leaf with a path following a pos
    signal input leaf;
    signal input path[k];
    signal input pathPositions[k];

    signal output out;

    // hash of the first two entries in the Merkle proof
    component merkle_root[k];
    merkle_root[0] = Poseidon(2);
    merkle_root[0].inputs[0] <== leaf - pathPositions[0]* (leaf - path[0]);
    merkle_root[0].inputs[1] <== path[0] - pathPositions[0]* (path[0] - leaf);

    // hash of all other entries in the Merkle proof
    for (var v = 1; v < k; v++) {
        merkle_root[v] = Poseidon(2);
        merkle_root[v].inputs[0] <== merkle_root[v-1].out - pathPositions[v]* (merkle_root[v-1].out - path[v]);
        merkle_root[v].inputs[1] <== path[v] - pathPositions[v]* (path[v] - merkle_root[v-1].out);
    }

    // output computed Merkle root
    out <== merkle_root[k-1].out;
}