pragma circom 2.0.0;
include "../hash_commitment/hash_array_original/hash_array_res.circom";
include "../hash_commitment/hash_array_original/hash_array.circom";
include "../exp_elliptic/circom-ecdsa/circuits/secp256k1.circom";
include "../circomlib/circuits/bitify.circom";

template encryption(N, logN, n, k) {  

    signal input comm_e;

    signal input X_[N];
    signal input enc[N];

    signal input pk1[logN][2][k];
    signal input pk2[logN][2][k];

    signal input rand[logN][k];

    signal y_k_j_k[N][logN][2][k];
    component num_to_bits[N];

    component exp[N][logN];
    signal res_exp[N][logN][2][k];

    signal j_k[N][logN];
    signal bin[N][logN];

    component poseidon[N][logN];
    signal res_poseidon[N][logN];

    var sum[N];
    signal res_enc[N];

    component hash_e = Commitment(N);

    for (var i=0; i<N; i++) {
        hash_e.inputs[i] <== enc[i];
    }
    hash_e.comm <== comm_e;

    for (var idx = 0; idx < N; idx++) {
        sum[idx] = 0;

        num_to_bits[idx] = Num2Bits(logN);
        num_to_bits[idx].in <== idx;

        for (var i=0; i<logN; i++) {
            bin[idx][i] <== num_to_bits[idx].out[logN-i-1];
        }

        for (var m = 1; m < logN+1; m++) {

            j_k[idx][m-1] <== bin[idx][m-1];

            for (var i=0; i<2; i++) {
                for (var j=0; j<k; j++) {
                    y_k_j_k[idx][m-1][i][j] <== j_k[idx][m-1]*(pk2[m-1][i][j] - pk1[m-1][i][j]) + pk1[m-1][i][j];
                }
            }

            exp[idx][m-1] =  Secp256k1ScalarMult(n, k);

            for (var j=0; j<k; j++) {
                exp[idx][m-1].scalar[j] <== rand[m-1][j];

                exp[idx][m-1].point[0][j] <== y_k_j_k[idx][m-1][0][j];
                exp[idx][m-1].point[1][j] <== y_k_j_k[idx][m-1][1][j];
            }

            for (var j=0; j<k; j++) {
                res_exp[idx][m-1][0][j] <== exp[idx][m-1].out[0][j];
                res_exp[idx][m-1][1][j] <== exp[idx][m-1].out[1][j];

            }

            poseidon[idx][m-1] = Commitment_res(2*k+logN);

            for (var i=0; i<k; i++) {
                poseidon[idx][m-1].inputs[i] <== res_exp[idx][m-1][0][i];
            }

            for (var i=k; i<2*k; i++) {
                poseidon[idx][m-1].inputs[i] <== res_exp[idx][m-1][1][i-k];
            }

            for (var i=2*k; i<2*k+logN; i++) {
                poseidon[idx][m-1].inputs[i] <== bin[idx][i-2*k];
            }
            

            res_poseidon[idx][m-1] <== poseidon[idx][m-1].comm;

            sum[idx] = sum[idx] + res_poseidon[idx][m-1];
        }

        res_enc[idx] <== sum[idx] + X_[idx];

        log(res_enc[idx]);
        res_enc[idx] === enc[idx];
    }
}

// component main {public [comm_e]} = encryption(4, 2, 64, 4);