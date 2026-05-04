pragma circom 2.1.5;

include "elGamal.circom";
include "circomlib/circuits/bitify.circom";

template ElGamalVoteVector(N) {
    // --- Public inputs ---
    signal input pk[2];             // Poll Owner Public Key
    
    // --- Outputs (Ciphertexts) ---
    signal output encVote[N][2][2]; // array of [C1_x, C1_y], [C2_x, C2_y]

    // --- Private inputs ---
    signal input vote[N];           // One-hot vector
    signal input r[N];              // Randomness for encryption

    // --- 1. Enforce one-hot vote vector ---
    signal partialSum[N];
    partialSum[0] <== vote[0];
    for (var i = 1; i < N; i++) {
        partialSum[i] <== partialSum[i-1] + vote[i];
    }
    partialSum[N-1] === 1;

    // --- 2. Enforce each vote[i] binary ---
    for (var i = 0; i < N; i++) {
        vote[i] * (vote[i] - 1) === 0;
    }

    // --- 3. Encrypt Vote ---
    component enc[N];

    for (var i = 0; i < N; i++) {
        enc[i] = ElGamal();
        
        enc[i].pk[0] <== pk[0];
        enc[i].pk[1] <== pk[1];
        enc[i].r <== r[i];
        enc[i].m <== vote[i];
        
        // C1 (x, y)
        encVote[i][0][0] <== enc[i].c1[0];
        encVote[i][0][1] <== enc[i].c1[1];
        
        // C2 (x, y)
        encVote[i][1][0] <== enc[i].c2[0];
        encVote[i][1][1] <== enc[i].c2[1];
    }
}

component main {public [pk]} = ElGamalVoteVector(8);
