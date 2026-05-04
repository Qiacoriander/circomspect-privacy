pragma circom 2.0.0;

include "./node_modules/circomlib/circuits/poseidon.circom";
include "./node_modules/circomlib/circuits/eddsaposeidon.circom";
include "./node_modules/circomlib/circuits/bitify.circom";
include "./if_gadgets.circom";
include "./tx_existence.circom";
include "./balance_existence.circom";
include "./balance_leaf.circom";
include "./get_merkle_root.circom";

template ProcessTxs(n, m) {
    // n is the depth of the balance tree 
    // m is the depth of the transactions tree,
    // so for each proof, we update 2**m transactions

    // STEP 0: initialize signals
    // transaction tree initial root
    signal input txRoot;

    // path for proving tx in tx tree
    signal input txPathHashes[2**m][m];
    signal input txPathPositions[2**m][m];

    // Merkle root of old balance tree
    signal input currentState;

    // intermediate roots for all the transactions
    signal input intermediateRoots[2**(m + 1) + 1];

    // Merkle proof for sender account in old balance tree
    signal input senderPathHashes[2**m][n];
    signal input senderPathPositions[2**m][n];

    // Merkle proof for receiver account in old balance tree
    signal input receiverPathHashes[2**m][n];
    signal input receiverPathPositions[2**m][n];

    // tx info, 10 fields
    signal input senderX[2**m]; //sender address x coordinate
    signal input senderY[2**m]; //sender address y coordinate
    signal input senderIndex[2**m]; // sender account leaf index
    signal input receiverX[2**m]; // receiver address x coordinate
    signal input receiverY[2**m]; // receiver address y coordinate
    signal input receiverIndex[2**m]; // receiver account leaf index
    signal input senderNonce[2**m]; // sender account nonce
    signal input amount[2**m]; // amount being transferred
    signal input senderTokenType[2**m]; // sender token type
    signal input R8x[2**m]; // sender signature
    signal input R8y[2**m]; // sender signature
    signal input S[2**m]; // sender signature

    // additional account info, not included in tx
    signal input senderTokenBalance[2**m]; // sender token balance
    signal input receiverTokenBalance[2**m]; // receiver token balance
    signal input receiverNonce[2**m]; // receiver account nonce
    signal input receiverTokenType[2**m]; // receiver token type

    // new balance tree Merkle root 
    signal output out;

    // limiting nonce to 100
    var NONCE_MAX_VALUE = 100;  

    // constant zero address -- to process withdrawals
    var ZERO_ADDRESS_X = 0;
    var ZERO_ADDRESS_Y = 0;

    component txExistence[2**m];
    component senderExistence[2**m];
    component ifBothHighForceEqual[2**m];
    component newSender[2**m];
    component computedRootFromNewSender[2**m];
    component receiverExistence[2**m];
    component newReceiver[2**m];
    component allLow[2**m];
    component ifThenElse[2**m];
    component computedRootFromNewReceiver[2**m];

    // initial state should be the current state at the start
    currentState === intermediateRoots[0];

    // checking all transactions
    for (var i = 0; i < 2**m ; i++) {

        // TODO: verify that provided senderIndex is the actual one by comparing it with the result of moving through reversed pathPositions and arriving at a leaf
        // If it is not, then the senderIndex is not the real one

        // verifying senderIndex
        var from_idx = 0;
        for (var k = n - 1; k >= 0; k--) {
            from_idx += senderPathPositions[i][k] * 2 ** k;
        }
        assert(from_idx == senderIndex[i]);

        // verifying receiverIndex
        var to_idx = 0;
        for (var k = n - 1; k >= 0; k--) {
            to_idx += receiverPathPositions[i][k] * 2 ** k;
        }
        assert(to_idx == receiverIndex[i]);

        // transaction existence and signature check
        txExistence[i] = TxExistence(m);
        txExistence[i].senderX <== senderX[i];
        txExistence[i].senderY <== senderY[i];
        txExistence[i].senderIndex <== senderIndex[i];
        txExistence[i].receiverX <== receiverX[i];
        txExistence[i].receiverY <== receiverY[i];
        txExistence[i].nonce <== senderNonce[i];
        txExistence[i].amount <== amount[i];
        txExistence[i].senderTokenType <== senderTokenType[i];

        txExistence[i].txRoot <== txRoot;

        for (var j = 0; j < m; j++) {
            txExistence[i].pathPositions[j] <== txPathPositions[i][j];
            txExistence[i].path[j] <== txPathHashes[i][j];
        }
        
        txExistence[i].R8x <== R8x[i];
        txExistence[i].R8y <== R8y[i];
        txExistence[i].S <== S[i];

        // sender existence check
        senderExistence[i] = BalanceExistence(n);
        senderExistence[i].x <== senderX[i];
        senderExistence[i].y <== senderY[i];
        senderExistence[i].tokenBalance <== senderTokenBalance[i];
        senderExistence[i].nonce <== senderNonce[i];
        senderExistence[i].tokenType <== senderTokenType[i];

        senderExistence[i].balanceRoot <== intermediateRoots[2*i];
        for (var j = 0; j < n; j++){
            senderExistence[i].pathPositions[j] <== senderPathPositions[i][j];
            senderExistence[i].path[j] <== senderPathHashes[i][j];
        }

        // balance checks - TODO: add fees
        assert(senderTokenBalance[i] - amount[i] <= senderTokenBalance[i]);
        assert(receiverTokenBalance[i] + amount[i] >= receiverTokenBalance[i]);
        assert(senderNonce[i] != NONCE_MAX_VALUE);

        // check token types for non withdrawals
        ifBothHighForceEqual[i] = IfBothHighForceEqual();
        ifBothHighForceEqual[i].check1 <== receiverX[i];  // If we are not sending to ZERO_ADDRESS, will force token types to be the same
        ifBothHighForceEqual[i].check2 <== receiverY[i];
        ifBothHighForceEqual[i].a <== receiverTokenType[i];
        ifBothHighForceEqual[i].b <== senderTokenType[i];

        // subtract amount from sender balance and increase sender nonce
        newSender[i] = BalanceLeaf();
        newSender[i].x <== senderX[i];
        newSender[i].y <== senderY[i];
        newSender[i].tokenBalance <== senderTokenBalance[i] - amount[i];
        newSender[i].nonce <== senderNonce[i] + 1;
        newSender[i].tokenType <== senderTokenType[i];

        // get intermediate root from new sender leaf
        computedRootFromNewSender[i] = GetMerkleRoot(n);
        computedRootFromNewSender[i].leaf <== newSender[i].out;
        for (var j = 0; j < n; j++) {
            computedRootFromNewSender[i].path[j] <== senderPathHashes[i][j];
            computedRootFromNewSender[i].pathPositions[j] <== senderPathPositions[i][j];
        }

        //check that the intermediate root is consistent with input
        computedRootFromNewSender[i].out === intermediateRoots[2*i + 1];

        // receiver existence check in intermediate root from new sender
        receiverExistence[i] = BalanceExistence(n);
        receiverExistence[i].x <== receiverX[i];
        receiverExistence[i].y <== receiverY[i];
        receiverExistence[i].tokenBalance <== receiverTokenBalance[i];
        receiverExistence[i].nonce <== receiverNonce[i];
        receiverExistence[i].tokenType <== receiverTokenType[i];

        receiverExistence[i].balanceRoot <== intermediateRoots[2*i + 1];
        for (var j = 0; j < n; j++) {
            receiverExistence[i].path[j] <== receiverPathHashes[i][j];
            receiverExistence[i].pathPositions[j] <== receiverPathPositions[i][j] ;
        }

        // check receiver after incrementing
        newReceiver[i] = BalanceLeaf();
        newReceiver[i].x <== receiverX[i];
        newReceiver[i].y <== receiverY[i];

        // if receiver is zero address, do not change balance
        // otherwise add amount to receiver balance
        allLow[i] = AllLow(2);
        allLow[i].in[0] <== receiverX[i];
        allLow[i].in[1] <== receiverY[i];

        ifThenElse[i] = IfAThenBElseC();
        ifThenElse[i].aCond <== allLow[i].out;
        ifThenElse[i].bBranch <== receiverTokenBalance[i];
        ifThenElse[i].cBranch <== receiverTokenBalance[i] + amount[i];

        newReceiver[i].tokenBalance <== ifThenElse[i].out;
        newReceiver[i].nonce <== receiverNonce[i];
        newReceiver[i].tokenType <== receiverTokenType[i];

        // get intermediate root from new receiver leaf
        computedRootFromNewReceiver[i] = GetMerkleRoot(n);
        computedRootFromNewReceiver[i].leaf <== newReceiver[i].out;
        for (var j = 0; j < n; j++) {
            computedRootFromNewReceiver[i].path[j] <== receiverPathHashes[i][j];
            computedRootFromNewReceiver[i].pathPositions[j] <== receiverPathPositions[i][j];
        }

        // check that intermediate root is consistent with input
        computedRootFromNewReceiver[i].out === intermediateRoots[2*i + 2];
    }

    out <== computedRootFromNewReceiver[2**m - 1].out;
    
}

component main {public [txRoot, currentState, senderIndex, receiverIndex, amount]} = ProcessTxs(4, 2);