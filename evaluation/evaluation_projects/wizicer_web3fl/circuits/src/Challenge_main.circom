pragma circom 2.2.0;
include "./Challenge.circom";

component main { public [P, round_number] } = ChallengeProof(10, 20, 16);
