pragma circom 2.0.0;

include "../utils/poseidon.circom";

template MerkleTree(nLevels) {
    signal input leaves[2**nLevels];
    signal output root;

    var nLeaves = 2**nLevels;
    var nNodes = nLeaves - 1;
    signal nodes[nNodes];
component poseidon[nLeaves - 1];

    // Compute Merkle tree
    for (var i = 0; i < nLeaves - 1; i++) {
        poseidon[i] = Poseidon(2);
        poseidon[i].inputs[0] <== i < nLeaves / 2 ? leaves[i*2] : nodes[i - nLeaves/2];
        poseidon[i].inputs[1] <== i < nLeaves / 2 ? leaves[i*2 + 1] : nodes[i - nLeaves/2 + 1];
        nodes[i] <== poseidon[i].out;
    }

    root <== nodes[nNodes - 1];
}