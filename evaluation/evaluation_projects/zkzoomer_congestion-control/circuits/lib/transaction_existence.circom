pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/eddsaposeidon.circom";
include "./transaction_leaf.circom";
include "./leaf_existence.circom";

// Verifies that a transaction exists within a tree, and that it was signed by the sending address.
template TransactionExistence(k) {
    // transaction data
    signal input fromX;
    signal input fromY;
    signal input toX;
    signal input toY;
    signal input nonce;
    signal input amount;
    
    // transaction Merkle tree data
    signal input treeSiblings[k];
    signal input treePathIndices[k];
    
    // signature data
    signal input R8x;
    signal input R8y;
    signal input S;

    signal output out;

    // computing the transaction leaf -- hash of the data
    component txLeaf = TransactionLeaf();
    txLeaf.fromX <== fromX;
    txLeaf.fromY <== fromY;
    txLeaf.toX <== toX;
    txLeaf.toY <== toY;
    txLeaf.nonce <== nonce;
    txLeaf.amount <== amount;

    // computing the Merkle root and verifying presence
    component txExistence = LeafExistence(k);
    txExistence.leaf <== txLeaf.out;
    for (var q = 0; q < k; q++) {
        txExistence.treeSiblings[q] <== treeSiblings[q];
        txExistence.treePathIndices[q] <== treePathIndices[q];
    }

    // verifying appropriate signature
    component verifier = EdDSAPoseidonVerifier();
    verifier.enabled <== 1;
    verifier.Ax <== fromX;
    verifier.Ay <== fromY;
    verifier.R8x <== R8x;
    verifier.R8y <== R8y;
    verifier.S <== S;
    verifier.M <== txLeaf.out;

    out <== txExistence.out;
}
