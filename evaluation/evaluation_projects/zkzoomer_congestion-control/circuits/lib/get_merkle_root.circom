pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";

// Gets the root of a given Merkle tree, where k is its depth
template GetMerkleRoot(k) {
    // The root is achieved by hashing a leaf following a path
    signal input leaf;
    signal input treeSiblings[k];
    signal input treePathIndices[k];

    signal output out;

    // hash of the first two entries in the Merkle proof
    component merkleRoot[k];
    merkleRoot[0] = Poseidon(2);
    merkleRoot[0].inputs[0] <== leaf - treePathIndices[0]* (leaf - treeSiblings[0]);
    merkleRoot[0].inputs[1] <== treeSiblings[0] - treePathIndices[0]* (treeSiblings[0] - leaf);

    // hash of all other entries in the Merkle proof
    for (var i = 1; i < k; i++) {
        merkleRoot[i] = Poseidon(2);
        merkleRoot[i].inputs[0] <== merkleRoot[i-1].out - treePathIndices[i]* (merkleRoot[i-1].out - treeSiblings[i]);
        merkleRoot[i].inputs[1] <== treeSiblings[i] - treePathIndices[i]* (treeSiblings[i] - merkleRoot[i-1].out);
    }

    // output computed Merkle root
    out <== merkleRoot[k-1].out;
}
