pragma circom 2.1.5;

include "elGamal.circom";
include "circomlib/circuits/comparators.circom";

template ElGamalVoteScalar(N) {
    // --- Public inputs ---
    signal input pk[2];             // Poll Owner Public Key (EC Point)

    // --- Private inputs ---
    signal input selectedOption;    // Which option to vote for (0 to N-1)
    signal input r;                 // Encryption randomness

    // --- Outputs ---
    signal output c1[2];            // ElGamal C1 = r * G (EC Point)
    signal output c2[2];            // ElGamal C2 = r * PK + selectedOption * G (EC Point)

    // --- 1. Validate selectedOption is in range [0, N) ---
    component rangeCheck = LessThan(8);
    rangeCheck.in[0] <== selectedOption;
    rangeCheck.in[1] <== N;
    rangeCheck.out === 1;

    // --- 2. Encrypt the selectedOption (Exponential ElGamal on BabyJubJub) ---
    // C1 = r * G
    // C2 = r * PK + selectedOption * G
    // Decryption: M = C2 - sk*C1 = selectedOption*G, then solve DLOG via BSGS
    component enc = ElGamal();
    enc.pk[0] <== pk[0];
    enc.pk[1] <== pk[1];
    enc.r <== r;
    enc.m <== selectedOption;

    c1[0] <== enc.c1[0];
    c1[1] <== enc.c1[1];
    c2[0] <== enc.c2[0];
    c2[1] <== enc.c2[1];
}

component main {public [pk]} = ElGamalVoteScalar(8);
