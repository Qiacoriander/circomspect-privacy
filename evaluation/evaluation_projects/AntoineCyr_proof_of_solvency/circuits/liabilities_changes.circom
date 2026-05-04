//inputs, merkle root, 

pragma circom 2.0.0;
include "./merkle.circom";
include "./utils.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// Define a template for liabilities proof circuit
template liabilities(levels, changes) {
    // Constants for balance validation
    var DEFAULT_MAX_BALANCE_BITS = 100;  // Maximum bits for balance (supports up to 2^100)
    // Validate template parameters
    assert(levels > 0 && levels <= 32);  // Reasonable tree depth bounds
    assert(changes > 0 && changes <= 1000);  // Reasonable number of changes
    
    // Define inputs
    signal input oldUserHash[changes];
    signal input oldValues[changes];
    signal input newUserHash[changes];
    signal input newValues[changes];
    signal input tempHash[changes+1];
    signal input tempSum[changes+1];
    signal input oldSum;
    signal input oldRootHash;
    signal input neighborsSum[changes][levels];
    signal input neighborsHash[changes][levels];
    signal input neighborsBinary[changes][levels];

    // Define outputs
    signal output newRootHash;
    signal output newSum;

    // Calculate newRootHash and newSum
    newRootHash <== tempHash[changes ];
    newSum <== tempSum[changes];
    oldSum === tempSum[0];
    oldRootHash === tempHash[0];
    
    var currentSum = oldSum;

    // Part 1: Check validity of new values
    signal sumNodes[2][changes][levels+1];
    signal hashNodes[2][changes][levels+1];
    component balanceCheck[changes];

    // Iterate through each change
    for (var i = 0; i < changes; i++) {
        //define first nodes values
        sumNodes[0][i][0] <== oldValues[i];
        hashNodes[0][i][0] <== oldUserHash[i];
        sumNodes[1][i][0] <== newValues[i];
        hashNodes[1][i][0] <== newUserHash[i];

        // Calculate currentSum
        currentSum = currentSum + newValues[i] - oldValues[i];

        // Perform non-negative balance validation (allows 0 balances)
        balanceCheck[i] = NonNegativeBalanceCheck(DEFAULT_MAX_BALANCE_BITS);
        balanceCheck[i].balance <== newValues[i];
        balanceCheck[i].out === 1;
    }

    // Assert newSum equals currentSum
    newSum === currentSum;

    // Part 2: Check validity of old and new paths
    // Ensure that old root + change = temp root
   
    component merkleSumLevel[2][changes][levels];

    for (var j = 0; j < changes; j++){
        for  (var i = 0; i<levels; i++){
            // Old state verification
            merkleSumLevel[0][j][i] = MerkleSumLevel();
            merkleSumLevel[0][j][i].hashNode <== hashNodes[0][j][i];
            merkleSumLevel[0][j][i].sumNode <== sumNodes[0][j][i];
            merkleSumLevel[0][j][i].neighborHash <== neighborsHash[j][i];
            merkleSumLevel[0][j][i].neighborSum <== neighborsSum[j][i];
            merkleSumLevel[0][j][i].neighborBinary <== neighborsBinary[j][i];

            hashNodes[0][j][i+1] <== merkleSumLevel[0][j][i].hashOut;
            sumNodes[0][j][i+1] <== merkleSumLevel[0][j][i].sumOut;

            // New state verification
            merkleSumLevel[1][j][i] = MerkleSumLevel();
            merkleSumLevel[1][j][i].hashNode <== hashNodes[1][j][i];
            merkleSumLevel[1][j][i].sumNode <== sumNodes[1][j][i];
            merkleSumLevel[1][j][i].neighborHash <== neighborsHash[j][i];
            merkleSumLevel[1][j][i].neighborSum <== neighborsSum[j][i];
            merkleSumLevel[1][j][i].neighborBinary <== neighborsBinary[j][i];

            hashNodes[1][j][i+1] <== merkleSumLevel[1][j][i].hashOut;
            sumNodes[1][j][i+1] <== merkleSumLevel[1][j][i].sumOut;
        }

    // Assert value is in old temp hash
    hashNodes[0][j][levels] === tempHash[j];

    // Assert new temp hash is valid
    hashNodes[1][j][levels] === tempHash[j+1];

    // Assert old sum is in tempSum
    sumNodes[0][j][levels] === tempSum[j];

    // Assert new sum is valid
    sumNodes[1][j][levels] === tempSum[j+1];
    }
}

// Define main component
component main {public [oldSum]} = liabilities(2, 1);
