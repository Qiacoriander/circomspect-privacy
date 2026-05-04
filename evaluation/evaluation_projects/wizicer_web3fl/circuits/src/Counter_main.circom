pragma circom 2.2.0;
include "./Counter.circom";

component main { public [round_number] } = CounterChallengeProof(10, 20, 16);