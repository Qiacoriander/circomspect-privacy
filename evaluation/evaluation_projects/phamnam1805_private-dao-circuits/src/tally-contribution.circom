pragma circom 2.1.4;
include "./libs/reveal-contribution.circom";

// n: number of committee members
component main {public [senderIndex, C, u, c, R, D]} = RevealContribute(5, 3, 3);
// component main {public [u, c, R, D]} = RevealContribute(5, 3);
// component main {public [u, c, R, D]} = RevealContribute(5, 3);