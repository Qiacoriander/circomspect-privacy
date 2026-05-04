pragma circom 2.0.0;
include "../permutation/permutation.circom";
include "../hash_commitment/hash_array_original/hash_array.circom";
include "../exp_elliptic/circom-ecdsa/circuits/secp256k1.circom";
include "../encryption/encryption.circom";
// include "../hash_commitment/hash_array_long_inputs/hash_array.circom";

template protocol(N, logN, n, k) {  
    signal input comm_X;
    signal input comm_X_;
    signal input comm_e;
    signal input comm_y;
    signal input comm_gamma;

    signal input enc[N];
    signal input rand[logN][k];

    signal input X[N];
    signal input X_[N];

    signal input P[N][N]; 
    signal input PA[N][N];

    signal input c_OT[2][k];
    signal input pk1[logN][2][k];
    signal input pk2[logN][2][k];

    signal input r_p;
    signal input comm_r_p;

    component encr = encryption(N, logN, n, k);
    
    encr.comm_e <== comm_e;

    for (var i=0; i<N; i++) {
        encr.X_[i] <== X_[i];
        encr.enc[i] <== enc[i];
    }

    for (var i=0; i<logN; i++) {
        for (var j=0; j<k; j++) {
            encr.rand[i][j] <== rand[i][j];

            encr.pk1[i][0][j] <== pk1[i][0][j];
            encr.pk1[i][1][j] <== pk1[i][1][j];

            encr.pk2[i][0][j] <== pk2[i][0][j];
            encr.pk2[i][1][j] <== pk2[i][1][j];
        }
    }

    component add_two_points[logN];

    for (var i=0; i<logN; i++) {
        add_two_points[i] = Secp256k1AddUnequal(n, k);

        for (var j=0; j<k; j++) {
            add_two_points[i].a[0][j] <== pk1[i][0][j];
            add_two_points[i].a[1][j] <== pk1[i][1][j];

            add_two_points[i].b[0][j] <== pk2[i][0][j];
            add_two_points[i].b[1][j] <== pk2[i][1][j];
        }

        for (var j=0; j<k; j++) {
            log(add_two_points[i].out[0][j]);
            log(add_two_points[i].out[1][j]);

            add_two_points[i].out[0][j] === c_OT[0][j];
            add_two_points[i].out[1][j] === c_OT[1][j];

            
        }

        // pk1[i] + pk2[i] === c_OT;
    }

    component perm = Permutation(N);
    
    for (var i=0; i<N; i++) {
        perm.A[i] <== X[i];
    }

    for (var i=0; i<N; i++) {
        perm.B[i] <== X_[i];
    }

    for (var i=0; i<N; i++) {
        for (var j=0; j<N; j++) {
            perm.P[i][j] <== P[i][j];
        }
    }

    for (var i=0; i<N; i++) {
        for (var j=0; j<N; j++) {
            perm.PA[i][j] <== PA[i][j];
        }
    }

    component hash_X = Commitment(N);

    for (var i=0; i<N; i++) {
        hash_X.inputs[i] <== X[i];
    }
    hash_X.comm <== comm_X;

    component hash_X_ = Commitment(N);

    for (var i=0; i<N; i++) {
        hash_X_.inputs[i] <== X_[i];
    }
    hash_X_.comm <== comm_X_;

    component hash_y = Commitment(logN*2*k);

    var m=0;
    for (var i=0; i<logN; i++) {
        for (var j=0; j<k; j++) {
            hash_y.inputs[m] <==pk1[i][0][j];
            m++;
        } 
        for (var j=0; j<k; j++) {
            hash_y.inputs[m] <==pk1[i][1][j];
            m++;
        } 
    }
    hash_y.comm <== comm_y;

    component hash_rand = Commitment(logN*k);

    m=0;
    for (var i=0; i<logN; i++) {
        for (var j=0; j<k; j++) {
            hash_rand.inputs[m] <==rand[i][j];
            m++;
        } 
    }
    hash_rand.comm <== comm_gamma;

    component hash_r_p = Commitment(1);

    hash_r_p.inputs[0] <== r_p;
    hash_r_p.comm <== comm_r_p;

}

component main {public [comm_X, comm_X_, c_OT, comm_e, comm_y, comm_gamma, comm_r_p]} = protocol(4, 2, 64, 4);
// component main {public [comm_X, comm_X_]} = protocol(2, 1, 64, 4);