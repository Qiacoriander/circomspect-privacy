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

template CounterChallengeProof(n_participants, T, chunk_size) {

    // === Public Inputs ===
    signal input round_number;        // round number

    // === Public Output ===
    signal output C1;                 // Hash of V1
    signal output C2;                 // Hash of V2
    signal output aggregator;         // aggregator public key = Poseidon( [Ax, Ay] )

    // === Private Inputs ===
    signal input V2[n_participants][T];        // Data matrix
    signal input sig_V1[3];                    // [R8x, R8y, S]
    signal input sig_V2[3];                    // [R8x, R8y, S]
    signal input agg_pubkey[2];                // aggregator public key = [Ax, Ay]
    signal input salt;                         // salt

    // === Internal Logic ===

    // 1. check V2
    signal r2[T] <== Num2Selector(T)(round_number + 1);
    VerifyMatrixRoundData(n_participants, T)(r2, V2);

    // 2. construct V1 from V2
    signal r1[T] <== Num2Selector(T)(round_number);
    signal V1[n_participants][T];
    for (var i = 0; i < n_participants; i++) {
        for (var t = 0; t < T; t++) {
            V1[i][t] <== V2[i][t] * r1[t];
        }
    }

    // 3. hash V1 and V2
    C1 <== MatrixHasher(n_participants, T, chunk_size)(V1, salt);
    C2 <== MatrixHasher(n_participants, T, chunk_size)(V2, salt);

    // 4. verify aggregator is a valid public key
    aggregator <== Poseidon(2)(agg_pubkey);

    // 5. verify sig_V1 and sig_V2 are valid
    signal valid_sigV1 <== VerifySignature()(agg_pubkey, sig_V1, C1);
    valid_sigV1 === 1;
    signal valid_sigV2 <== VerifySignature()(agg_pubkey, sig_V2, C2);
    valid_sigV2 === 1;
}

