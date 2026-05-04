pragma circom 2.0.0;

include "./get_merkle_root.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";

template LeafExistenceVerifier(depth){
    
    signal input leafNode;
    signal input expectedRoot;
    signal input siblingHashes[depth];
    signal input siblingPositions[depth];

    component merkleRootCalculator = GetMerkleRoot(depth);
    merkleRootCalculator.leafNode <== leafNode;

    for (var index = 0; index < depth; index++){
        merkleRootCalculator.siblingHashes[index] <== siblingHashes[index];
        merkleRootCalculator.siblingPositions[index] <== siblingPositions[index];
    }

    expectedRoot === merkleRootCalculator.merkleRoot;
}

component main {public [leafNode, expectedRoot, siblingHashes, siblingPositions]} = LeafExistenceVerifier(2);
