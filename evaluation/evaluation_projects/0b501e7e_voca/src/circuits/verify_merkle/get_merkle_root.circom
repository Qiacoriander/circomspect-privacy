pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

template GetMerkleRoot(depth){

    signal input leafNode;
    signal input siblingHashes[depth];
    signal input siblingPositions[depth];

    signal output merkleRoot;


    component poseidonHashes[depth];
    poseidonHashes[0] = Poseidon(2);
    poseidonHashes[0].inputs[0] <== leafNode - siblingPositions[0] * (leafNode - siblingHashes[0]);
    poseidonHashes[0].inputs[1] <== siblingHashes[0] - siblingPositions[0] * (siblingHashes[0] - leafNode);

    for (var i = 1; i < depth; i++){
        poseidonHashes[i] = Poseidon(2);
        poseidonHashes[i].inputs[0] <== poseidonHashes[i-1].out - siblingPositions[i] * (poseidonHashes[i-1].out - siblingHashes[i]);
        poseidonHashes[i].inputs[1] <== siblingHashes[i] - siblingPositions[i] * (siblingHashes[i] - poseidonHashes[i-1].out);
    }

    merkleRoot <== poseidonHashes[depth-1].out;
}

// component main = GetMerkleRoot(2);
