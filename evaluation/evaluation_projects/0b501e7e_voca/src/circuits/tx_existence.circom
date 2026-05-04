pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/eddsaposeidon.circom";
include "./tx_leaf.circom";
include "./leaf_existence.circom";

template TxExistence(k) {
    // Verifies that a transaction exists within a tree,
    // and that it was signed by the address

    // transaction data
    signal input senderX;
    signal input senderY;
    signal input senderIndex;
    signal input receiverX;
    signal input receiverY;
    signal input nonce;
    signal input amount;
    signal input senderTokenType;
    
    // transaction Merkle tree data
    signal input txRoot;
    signal input path[k];
    signal input pathPositions[k];
    
    // signature data
    signal input R8x;
    signal input R8y;
    signal input S;

    // computing the transaction leaf -- hash of the data
    component txLeaf = TxLeaf();
    txLeaf.senderX <== senderX;
    txLeaf.senderY <== senderY;
    txLeaf.senderIndex <== senderIndex;
    txLeaf.receiverX <== receiverX;
    txLeaf.receiverY <== receiverY;
    txLeaf.nonce <== nonce;
    txLeaf.amount <== amount;
    txLeaf.senderTokenType <== senderTokenType;

    // computing the Merkle root and verifying presence
    component txExistence = LeafExistence(k);
    txExistence.leaf <== txLeaf.out;
    txExistence.root <== txRoot;
    
    for (var q = 0; q < k; q++) {
        txExistence.path[q] <== path[q];
        txExistence.pathPositions[q] <== pathPositions[q];
    }

    // verifying appropriate signature
    component verifier = EdDSAPoseidonVerifier();
    verifier.enabled <== 1;
    verifier.Ax <== senderX;
    verifier.Ay <== senderY;
    verifier.R8x <== R8x;
    verifier.R8y <== R8y;
    verifier.S <== S;
    verifier.M <== txLeaf.out;

}