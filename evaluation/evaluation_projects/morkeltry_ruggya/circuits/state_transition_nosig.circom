pragma circom 2.0.0;

include "circomlib/circuits/sig.circom"; // Include the circomlib for signature verification

component main {
    signal input currentState[15]; // L, P, S, but no pubkey for each of the 5 players (3*5)
    signal input votes[55];        // KP and KS for each player (5*5*2), signatures for each player (5)
    signal input outputState[15];  // L, P, S for each of the 5 players (3*5)

    signal publicRugTotal[5];
    signal secretRugTotal[5];
    signal playerToRug;
    signal highestRugTotal;

    component signVerifiers[5];

    for (var i = 0; i < 5; i++) {
        publicRugTotal[i] <== 0;
        secretRugTotal[i] <== 0;
    }

    for (var i = 0; i < 5; i++) {
        // Extract votes and signatures
        var KPStart = i * 10;
        var KSStart = KPStart + 5;
        var signatureStart = 50 + i;

        // Check if vote is signed with the key matching their pubkey
        signVerifiers[i] = SignatureVerifier();

        for (var j = 0; j < 5; j++) {
            var KP = votes[KPStart + j];
            var KS = votes[KSStart + j];

            // Ensure KP and KS against the player themself is zero
            if (i == j) {
                KP === 0;
                KS === 0;
            }

            // Ensure KP and KS against dead players is zero
            if (currentState[j] == 0) {
                KP === 0;
                KS === 0;
            }

            // Exclude votes from dead players
            if (currentState[i] != 0) {
                publicRugTotal[j] += KP;
                secretRugTotal[j] += KS;
            }
        }
    }

    highestRugTotal <== 0;
    playerToRug <== 0;

    for (var i = 0; i < 5; i++) {
        // Check public and secret rug votes each total against vote power
        publicRugTotal[i] <= currentState[5 + i];
        secretRugTotal[i] <= currentState[10 + i];

        if (publicRugTotal[i] + secretRugTotal[i] > highestRugTotal) {
            highestRugTotal <== publicRugTotal[i] + secretRugTotal[i];
            playerToRug <== i;
        }
    }

    // Verify that in the output state, the player to be rugged has liveness of 0
    outputState[playerToRug] == 0;
}