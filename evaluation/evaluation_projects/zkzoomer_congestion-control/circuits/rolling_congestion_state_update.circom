pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/switcher.circom";
include "./lib/account_leaf/rolling_congestion_account_leaf.circom";
include "./base/base_state_update.circom";

// Processes the base state update of 2**n accounts as a result of 2**m update transactions
template RollingCongestionStateUpdate(n, m, nBlocks) {
    // The block number for the last verification that was recorded on chain
    // Starts at 0 on deployment block
    signal input lastBlock;

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

    // SIMPLE STATE UPDATE -- ACCOUNT LEAF ADDITIONAL VALUES
    signal input toBalance[2**m];  // receiver account balance
    signal input toNonce[2**m];  // receiver account nonce

    // Congestion control values
    signal input fromCurrentPlan[2**m];
    signal input fromLastOnline[2**m];
    signal input fromNumberTransactions[2**m];
    signal input toCurrentPlan[2**m];
    signal input toLastOnline[2**m];
    signal input toNumberTransactions[2**m];

    signal output newAccountsRoot;

    // COMPUTING THE SENDER AND RECEIVER LEAVES -- ROLLING CONGESTION
    component senderLeaves[2**m][2];
    component receiverLeaves[2**m][2];

    // Components for verifying spam prevention
    component transactionCounterResets[2**m];
    component transactionCounters[2**m];
    component comparators[2**m];
    signal newLastOnlines[2**m];

    for (var i = 0; i < 2**m; i++) {
        // Initial state
        senderLeaves[i][0] = RollingCongestionAccountLeaf();
        senderLeaves[i][0].X <== fromX[i];
        senderLeaves[i][0].Y <== fromY[i];
        senderLeaves[i][0].balance <== fromBalance[i];
        senderLeaves[i][0].nonce <== fromNonce[i];
        senderLeaves[i][0].currentPlan <== fromCurrentPlan[i];
        senderLeaves[i][0].lastOnline <== fromLastOnline[i];
        senderLeaves[i][0].nTransactions <== fromNumberTransactions[i];

        // ROLLING CONGESTION SPAM PREVENTION
        newLastOnlines[i] <-- lastBlock \ nBlocks;
        newLastOnlines[i] * nBlocks === lastBlock;
        
        transactionCounterResets[i] = IsEqual();
        transactionCounterResets[i].in[0] <== fromLastOnline[i];
        transactionCounterResets[i].in[1] <== newLastOnlines[i];

        transactionCounters[i] = Switcher();
        transactionCounters[i].L <== fromNumberTransactions[i] + 1;
        transactionCounters[i].R <== 1;
        transactionCounters[i].sel <== transactionCounterResets[i].out;

        // Here we enforce that fromCurrentPlan[i] >= transactionCounters[i].outR, as the `transactionCounters` can only increase one by one
        comparators[i] = IsEqual();
        comparators[i].in[0] <== fromCurrentPlan[i] + 1;
        comparators[i].in[1] <== transactionCounters[i].outR;

        comparators[i].out === 0;

        // After debiting amount
        senderLeaves[i][1] = RollingCongestionAccountLeaf();
        senderLeaves[i][1].X <== fromX[i];
        senderLeaves[i][1].Y <== fromY[i];
        senderLeaves[i][1].balance <== fromBalance[i] - amount[i];
        senderLeaves[i][1].nonce <== fromNonce[i] + 1;
        senderLeaves[i][1].currentPlan <== fromCurrentPlan[i];
        senderLeaves[i][1].lastOnline <== newLastOnlines[i];
        senderLeaves[i][1].nTransactions <== transactionCounters[i].outR;
        
        // Initial state
        receiverLeaves[i][0] = RollingCongestionAccountLeaf();
        receiverLeaves[i][0].X <== toX[i];
        receiverLeaves[i][0].Y <== toY[i];
        receiverLeaves[i][0].balance <== toBalance[i];
        receiverLeaves[i][0].nonce <== toNonce[i];
        receiverLeaves[i][0].currentPlan <== toCurrentPlan[i];
        receiverLeaves[i][0].lastOnline <== toLastOnline[i];
        receiverLeaves[i][0].nTransactions <== toNumberTransactions[i];

        // After crediting amount
        receiverLeaves[i][1] = RollingCongestionAccountLeaf();
        receiverLeaves[i][1].X <== toX[i];
        receiverLeaves[i][1].Y <== toY[i];
        receiverLeaves[i][1].balance <== toBalance[i] + amount[i];
        receiverLeaves[i][1].nonce <== toNonce[i];
        receiverLeaves[i][1].currentPlan <== toCurrentPlan[i];
        receiverLeaves[i][1].lastOnline <== toLastOnline[i];
        receiverLeaves[i][1].nTransactions <== toNumberTransactions[i];
    }

    component baseStateUpdate = BaseStateUpdate(n, m);

    baseStateUpdate.txRoot <== txRoot;
    baseStateUpdate.accountsRoot <== accountsRoot;
        
    // FILLING UP ALL THE BASE STATE UPDATE VALUES
    for (var i = 0; i < 2**m; i++) {
        for (var j = 0; j < n; j++) {
            baseStateUpdate.txRootSiblings[i][j] <== txRootSiblings[i][j];
            baseStateUpdate.txRootPathIndices[i][j] <== txRootPathIndices[i][j];

            baseStateUpdate.fromTreeSiblings[i][j] <== fromTreeSiblings[i][j];
            baseStateUpdate.fromTreePathIndices[i][j] <== fromTreePathIndices[i][j];

            baseStateUpdate.toTreeSiblings[i][j] <== toTreeSiblings[i][j];
            baseStateUpdate.toTreePathIndices[i][j] <== toTreePathIndices[i][j];
        }

        baseStateUpdate.fromX[i] <== fromX[i];
        baseStateUpdate.fromY[i] <== fromY[i];
        baseStateUpdate.toX[i] <== toX[i];
        baseStateUpdate.toY[i] <== toY[i];
        baseStateUpdate.fromNonce[i] <== fromNonce[i];
        baseStateUpdate.amount[i] <== amount[i];

        baseStateUpdate.R8x[i] <== R8x[i];
        baseStateUpdate.R8y[i] <== R8y[i];
        baseStateUpdate.S[i] <== S[i];

        baseStateUpdate.fromBalance[i] <== fromBalance[i];

        baseStateUpdate.senderLeaves[i][0] <== senderLeaves[i][0].out;
        baseStateUpdate.senderLeaves[i][1] <== senderLeaves[i][1].out;

        baseStateUpdate.receiverLeaves[i][0] <== receiverLeaves[i][0].out;
        baseStateUpdate.receiverLeaves[i][1] <== receiverLeaves[i][1].out;
    }

    for (var k = 0; k < 2**(m + 1) + 1; k++) {
        baseStateUpdate.intermediateAccountsRoots[k] <== intermediateAccountsRoots[k];
    }

    newAccountsRoot <== baseStateUpdate.out;
}

component main {public [
    lastBlock,
    txRoot, 
    accountsRoot
]} = RollingCongestionStateUpdate(4, 2, 50);
