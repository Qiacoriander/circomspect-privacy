pragma circom 2.2.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/eddsa.circom";
include "../../node_modules/circomlib/circuits/babyjub.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";
include "../../node_modules/circomlib/circuits/pointbits.circom";
include "./lib/num2selector.circom";
include "./lib/verifySignature.circom";
include "./lib/matrixHasher.circom";
include "./lib/verifyMatrixRoundData.circom";
include "./lib/sumMatrixRow.circom";

template ChallengeProof(n_participants, T, chunk_size) {

    // === Public Inputs ===
    signal input P[n_participants];   // address of each participant
    signal input round_number;        // round number

    // === Public Output ===
    signal output C;                  // Hash of V
    signal output S[n_participants];
    signal output aggregator;          // aggregator public key = Poseidon( [Ax, Ay] )

    // === Private Inputs ===
    signal input V[n_participants][T];         // Data matrix
    signal input sig_V[3];                     // [R8x, R8y, S]
    signal input sig_P[n_participants][3];     // [R8x, R8y, S] for each participant
    signal input agg_pubkey[2];                // [Ax, Ay]
    signal input salt;                         // salt

    // === Internal Logic ===

    // 1. Compute row sums and check S[i] == sum_t V[i][t]
    signal round_selector[T] <== Num2Selector(T)(round_number);

    VerifyMatrixRoundData(n_participants, T)(round_selector, V);
    S <== SumMatrixRow(n_participants, T)(V, round_selector);

    // 2. hash V
    C <== MatrixHasher(n_participants, T, chunk_size)(V, salt);

    // 3. Verify aggregator is a valid public key
    aggregator <== Poseidon(2)(agg_pubkey);

    // 4. Verify sig_V is a valid signature of C by aggregator
    signal valid_sigV <== VerifySignature()(agg_pubkey, sig_V, C);
    valid_sigV === 1;

    // 5. Verify sig_P[i] is a valid signature of P[i] by aggregator
    signal valid_sigP[n_participants];
    for (var i = 0; i < n_participants; i++) {
        valid_sigP[i] <== VerifySignature()(agg_pubkey, sig_P[i], P[i]);
        valid_sigP[i] === 1;
    }
}
