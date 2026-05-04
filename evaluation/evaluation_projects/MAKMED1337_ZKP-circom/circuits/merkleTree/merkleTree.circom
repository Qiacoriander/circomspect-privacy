pragma circom 2.1.8;
include "../circom-ecdsa/zk-identity/eth.circom";
include "incrementalMerkleTree.circom";
include "circomlib/circuits/comparators.circom";

template AddressFromPK() {
    signal input pk[2][4];
    signal output address; // 160-bit integer

    signal pkBits[512] <== FlattenPubkey(64, 4)(pk);
    address <== PubkeyToAddress()(pkBits);
}

template CheckInclusionProof(levels) {
    signal input pk[2][4];
    signal input root;
    signal input proof[levels];
    signal input path[levels];

    signal output out;

    signal address <== AddressFromPK()(pk);

    signal dummy_proof[levels][1];
    for (var i = 0; i < levels; i++)
        dummy_proof[i][0] <== proof[i];
    signal correctRoot <== MerkleTreeInclusionProof(levels)(address, path, dummy_proof);
    out <== IsEqual()([root, correctRoot]);
}

