pragma circom 2.0.0;
include "./castVote.circom";

component main = castVote(63, __DEPTH__, __nCandiadates__, __nApproves__, __k__);