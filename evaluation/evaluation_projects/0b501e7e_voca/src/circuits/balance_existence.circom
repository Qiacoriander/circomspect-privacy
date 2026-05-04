pragma circom 2.0.0;

include "./balance_leaf.circom";
include "./leaf_existence.circom";

template BalanceExistence(k) {
    // Verifies that a given account is part of the balance tree
    // done by hashing the account data, and verifying that this leaf is inside the tree

    signal input x;
    signal input y;
    signal input tokenBalance;
    signal input nonce;
    signal input tokenType;

    signal input balanceRoot;
    signal input path[k];
    signal input pathPositions[k];

    component balanceLeaf = BalanceLeaf();
    balanceLeaf.x <== x;
    balanceLeaf.y <== y;
    balanceLeaf.tokenBalance <== tokenBalance;
    balanceLeaf.nonce <== nonce;
    balanceLeaf.tokenType <== tokenType;

    component balanceExistence = LeafExistence(k);
    balanceExistence.leaf <== balanceLeaf.out;
    balanceExistence.root <== balanceRoot;

    for (var s = 0; s < k; s++) {
        balanceExistence.path[s] <== path[s];
        balanceExistence.pathPositions[s] <== pathPositions[s];
    }
}