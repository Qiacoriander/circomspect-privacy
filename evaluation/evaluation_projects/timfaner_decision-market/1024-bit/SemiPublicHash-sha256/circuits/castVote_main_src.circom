pragma circom 2.0.0;
include "./castVote.circom";
// include "./castVote_dumpEncryptVote.circom";


component main = castVote(114, 9, 3, 1024, 256, __DEPTH__);