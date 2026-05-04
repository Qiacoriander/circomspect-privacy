pragma circom 2.1.5;

include "elGamalDecrypt.circom";

// Prove correct decryption of aggregated ElGamal ciphertexts (tally)
template ElGamalTallyDecrypt(N) {
    // --- Public inputs ---
    signal input pk[2];             // Public key
    signal input aggC1[N][2];       // Aggregated C1 per option
    signal input aggC2[N][2];       // Aggregated C2 per option
    signal input tally[N];          // Claimed tally per option

    // --- Private inputs ---
    signal input sk;                // Secret key

    // --- For each option: prove decryption ---
    component decrypt[N];
    
    for (var i = 0; i < N; i++) {
        decrypt[i] = ElGamalDecrypt();
        decrypt[i].pk[0] <== pk[0];
        decrypt[i].pk[1] <== pk[1];
        decrypt[i].c1[0] <== aggC1[i][0];
        decrypt[i].c1[1] <== aggC1[i][1];
        decrypt[i].c2[0] <== aggC2[i][0];
        decrypt[i].c2[1] <== aggC2[i][1];
        decrypt[i].m <== tally[i];
        decrypt[i].sk <== sk;
    }
}

component main {public [pk, aggC1, aggC2, tally]} = ElGamalTallyDecrypt(8);
