pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../lib/leaf_existence.circom";
include "../lib/transaction_existence.circom";

// Processes the base state update of 2**n accounts as a result of 2**m update transactions
// Only a single token type is supported. Support for withdrawals has also been removed for the sake of simplicity.
template BaseStateUpdate(n, m) {
    // Transaction tree root
    signal input txRoot;
    // Paths for transaction inclusion Merkle proofs
    signal input txRootSiblings[2**m][n];
    signal input txRootPathIndices[2**m][n];

    // Current state of the accounts tree
    signal input accountsRoot;
    // Intermediate states of the accounts tree after every update tx
    signal input intermediateAccountsRoots[2**(m + 1) + 1];

    // Paths for from account inclusion Merkle proofs
    signal input fromTreeSiblings[2**m][n];
    signal input fromTreePathIndices[2**m][n];

    // Paths for to account inclusion Merkle proofs
    signal input toTreeSiblings[2**m][n];
    signal input toTreePathIndices[2**m][n];

    // Transaction information
    signal input fromX[2**m];  // sender account x coordinate
    signal input fromY[2**m];  // sender account y coordinate
    signal input toX[2**m];  // reciever account x coordinate
    signal input toY[2**m];  // receiver account y coordinate
    signal input fromNonce[2**m];  // sender account nonce
    signal input amount[2**m];  // amount being transferred

    // Transaction signature validation
    signal input R8x[2**m];
    signal input R8y[2**m];
    signal input S[2**m];

    // Additional info not included in signed transaction
    signal input fromBalance[2**m];  // sender account balance

    // Sender leaves -- computed differently according to the congestion control being enforced
    signal input senderLeaves[2**m][2];
    // Receiver leaves -- computed differently according to the congestion control being enforced
    signal input receiverLeaves[2**m][2];

    // New accounts tree root
    signal output out;

    // Components for verifying the transaction existence within the tree
    component transactionExistence[2**m];

    // Components for verifying sender existence within tree
    component oldSenderExistence[2**m];
    component newSenderExistence[2**m];

    // Components for verifying receiver existence within tree
    component oldReceiverExistence[2**m];
    component newReceiverExistence[2**m];

    // Component for verifying no double spending is made
    component balanceCheck[2**m];

    // The first of the intermediate accounts root should be the current one
    accountsRoot === intermediateAccountsRoots[0];

    // Verify all transactions one by one
    for (var i = 0; i < 2**m; i++) {
        // Computing old sender tree
        oldSenderExistence[i] = LeafExistence(n);
        oldSenderExistence[i].leaf <== senderLeaves[i][0];
        for (var j = 0; j < n; j++) {
            oldSenderExistence[i].treeSiblings[j] <== fromTreeSiblings[i][j];
            oldSenderExistence[i].treePathIndices[j] <== fromTreePathIndices[i][j];
        }

        // Verifying sender existence within tree
        oldSenderExistence[i].out === intermediateAccountsRoots[2*i];

        // Update transaction existence and signature check
        transactionExistence[i] = TransactionExistence(n);
        transactionExistence[i].fromX <== fromX[i];
        transactionExistence[i].fromY <== fromY[i];
        transactionExistence[i].toX <== toX[i];
        transactionExistence[i].toY <== toY[i];
        transactionExistence[i].nonce <== fromNonce[i];
        transactionExistence[i].amount <== amount[i];

        for(var j = 0; j < n; j++) {
            transactionExistence[i].treeSiblings[j] <== txRootSiblings[i][j];
            transactionExistence[i].treePathIndices[j] <== txRootPathIndices[i][j];
        }

        transactionExistence[i].R8x <== R8x[i];
        transactionExistence[i].R8y <== R8y[i];
        transactionExistence[i].S <== S[i];

        transactionExistence[i].out === txRoot;

        // Balance check
        balanceCheck[i] = GreaterEqThan(252);
        balanceCheck[i].in[0] <== fromBalance[i];
        balanceCheck[i].in[1] <== amount[i];

        // Debited sender existence
        newSenderExistence[i] = LeafExistence(n);
        newSenderExistence[i].leaf <== senderLeaves[i][1];
        for (var j = 0; j < n; j++) {
            newSenderExistence[i].treeSiblings[j] <== fromTreeSiblings[i][j];
            newSenderExistence[i].treePathIndices[j] <== fromTreePathIndices[i][j];
        }

        newSenderExistence[i].out === intermediateAccountsRoots[2*i + 1];

        // Receiver existence in intermediate root
        oldReceiverExistence[i] = LeafExistence(n);
        oldReceiverExistence[i].leaf <== receiverLeaves[i][0];
        for (var j = 0; j < n; j++) {
            oldReceiverExistence[i].treeSiblings[j] <== toTreeSiblings[i][j];
            oldReceiverExistence[i].treePathIndices[j] <== toTreePathIndices[i][j];
        }

        oldReceiverExistence[i].out === intermediateAccountsRoots[2*i + 1];

        // Receiver existence in new root
        newReceiverExistence[i] = LeafExistence(n);
        newReceiverExistence[i].leaf <== receiverLeaves[i][0];
        for (var j = 0; j < n; j++) {
            newReceiverExistence[i].treeSiblings[j] <== toTreeSiblings[i][j];
            newReceiverExistence[i].treePathIndices[j] <== toTreePathIndices[i][j];
        }

        newReceiverExistence[i].out === intermediateAccountsRoots[2*i + 2];
    }

    // Setting the new accounts root
    out <== intermediateAccountsRoots[2**(m + 1)];
}
