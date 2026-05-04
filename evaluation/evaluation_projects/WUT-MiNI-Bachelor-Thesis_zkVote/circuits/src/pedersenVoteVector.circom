pragma circom 2.1.5;

include "pedersenCommitment.circom";

template PedersenVoteVector(N) {
    // === Private inputs ===
    signal input vote[N];          // v_i in {0,1}
    signal input blinder[N];       // r_i random scalars

    // === Public inputs ===
    signal input commitments[N][2];  // Pedersen commitments C_i = vote_i*G + blinder_i*H

    // === 1. Enforce one-hot vote vector ===
    signal partialSum[N];
    partialSum[0] <== vote[0];
    for (var i = 1; i < N; i++) {
        partialSum[i] <== partialSum[i-1] + vote[i];
    }
    partialSum[N-1] === 1;

    // Each vote[i] binary
    for (var i = 0; i < N; i++) {
        vote[i] * (vote[i] - 1) === 0;
    }

    // === 2. Verify Pedersen commitments ===
    component pedersen[N];
    for (var i = 0; i < N; i++) {
        pedersen[i] = PedersenCommitment();
        pedersen[i].vote <== vote[i];
        pedersen[i].blinder <== blinder[i];

        commitments[i][0] === pedersen[i].out[0];
        commitments[i][1] === pedersen[i].out[1];
    }
}

component main {public [commitments]} = PedersenVoteVector(8);