pragma circom 2.0.0;

// local imports
include "../../coordinator/qv/tallyVotes.circom";

// Params: stateTreeDepth, intStateTreeDepth, voteOptionTreeDepth
component main {public [index, numSignUps]} = TallyVotes(10, 1, 2);
