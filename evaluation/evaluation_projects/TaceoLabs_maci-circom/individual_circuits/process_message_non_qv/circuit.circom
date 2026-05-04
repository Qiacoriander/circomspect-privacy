pragma circom 2.0.0;

// local imports
include "../../coordinator/non-qv/processMessages.circom";

// Params: stateTreeDepth, batchSize, voteOptionTreeDepth
component main {public [
        numSignUps,
        index,
        batchEndIndex,
        actualStateTreeDepth,
        voteOptions
    ]}
= ProcessMessagesNonQv(10, 20, 2);
