pragma circom 2.0.0;

// local imports
include "../../voter/poll.circom";

// Params: stateTreeDepth
component main {public [pollId]} = PollJoining(10);
