pragma circom 2.0.0;

// local imports
include "../../coordinator/non-qv/tallyVotes.circom";

// Params: stateTreeDepth, intStateTreeDepth, voteOptionTreeDepth
component main {public [index, numSignUps]} = TallyVotesNonQv(10, 1, 2);
