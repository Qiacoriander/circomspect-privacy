pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "./tx_leaf.circom";
include "./leaf_existence.circom";

template TxExistence(k) {
    // Verifies that a transaction exists within a tree,
    // and that it was signed by the address

    // transaction data
    signal input from_x;
    signal input from_y;
    signal input from_index;
    signal input to_x;
    signal input to_y;
    signal input nonce;
    signal input amount;
    signal input senderTokenType;
    
    // transaction Merkle tree data
    signal input txRoot;
    signal input siblingHashes[k];
    signal input siblingPositions[k];
    
    // signature data
    signal input R8x;
    signal input R8y;
    signal input S;

    // computing the transaction leaf -- hash of the data
    component txLeaf = TxLeaf();
    txLeaf.from_x <== from_x;
    txLeaf.from_y <== from_y;
    txLeaf.from_index <== from_index;
    txLeaf.to_x <== to_x;
    txLeaf.to_y <== to_y;
    txLeaf.nonce <== nonce;
    txLeaf.amount <== amount;
    txLeaf.senderTokenType <== senderTokenType;

    // computing the Merkle root and verifying presence
    component txExistence = LeafExistence(k);
    txExistence.leafNode <== txLeaf.out;
    txExistence.root <== txRoot;
    
    for (var q = 0; q < k; q++) {
        txExistence.siblingHashes[q] <== siblingHashes[q];
        txExistence.siblingPositions[q] <== siblingPositions[q];
    }

    // verifying appropriate signature
    component verifier = EdDSAPoseidonVerifier();
    verifier.enabled <== 1;
    verifier.Ax <== from_x;
    verifier.Ay <== from_y;
    verifier.R8x <== R8x;
    verifier.R8y <== R8y;
    verifier.S <== S;
    verifier.M <== txLeaf.out;

}