pragma circom 2.0.0;
include "./castVote.circom";
// include "./castVote_dumpEncryptVote.circom";


// component main = castVote(114, 9, 3, 1024, 256, __DEPTH__);
component main {public [N, g, h_pow_N, merkleRoot, relayerAddr, fee, u, v, nullifierHash]} = castVote(114, 9, 3, 1024, 256, __DEPTH__);
