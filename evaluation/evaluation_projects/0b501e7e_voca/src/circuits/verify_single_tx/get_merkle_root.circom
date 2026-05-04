
pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

template GetMerkleRoot(k){
// k is depth of tree

    signal input leafNode;
    signal input siblingHashes[k];
    signal input siblingPositions[k];

    signal output merkleRoot;

    // hash of first two entries in tx Merkle proof
    component poseidonHashes[k];
    poseidonHashes[0] = Poseidon(2);
    poseidonHashes[0].inputs[0] <== leafNode - siblingPositions[0]* (leafNode - siblingHashes[0]);
    poseidonHashes[0].inputs[1] <== siblingHashes[0] - siblingPositions[0]* (siblingHashes[0] - leafNode);

    // hash of all other entries in tx Merkle proof
    for (var v = 1; v < k; v++){
        poseidonHashes[v] = Poseidon(2);
        poseidonHashes[v].inputs[0] <== poseidonHashes[v-1].out - siblingPositions[v]* (poseidonHashes[v-1].out - siblingHashes[v]);
        poseidonHashes[v].inputs[1] <== siblingHashes[v] - siblingPositions[v]* (siblingHashes[v] - poseidonHashes[v-1].out);
    }

    // output computed Merkle root
    merkleRoot <== poseidonHashes[k-1].out;
}

// component main = GetMerkleRoot(2)
