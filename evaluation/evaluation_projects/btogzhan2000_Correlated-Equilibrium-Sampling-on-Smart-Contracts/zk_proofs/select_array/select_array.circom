pragma circom 2.0.0;

include "../hash_commitment/hash_array_original/hash_array.circom";
include "../circomlib/circuits/comparators.circom";
include "../circomlib/circuits/bitify.circom";
include "maci/calculateTotal.circom";

template select_array(N, A1_size) {  
    signal input comm_XA;
    signal input comm_X;
    signal input comm_r;

    signal input X[N];
    signal input XA[A1_size][N];
    signal input r;
    signal input x_r;

    component hash_XA = Commitment(N + A1_size);

    var k=0;
    for (var i=0; i<A1_size; i++) {
        for (var j=0; j<N; j++) {
            hash_XA.inputs[k] <== XA[i][j];
            k++;
        }
    }
    hash_XA.comm <== comm_XA;

    component hash_X = Commitment(N);

    for (var i=0; i<N; i++) {
        hash_X.inputs[i] <== X[i];
    }
    hash_X.comm <== comm_X;

    component hash_r = Commitment(1);

    hash_r.inputs[0] <== r;
    hash_r.comm <== comm_r;


    component lessThan = LessThan(64);

    lessThan.in[0] <-- x_r;
    lessThan.in[1] <-- A1_size;

    1 === lessThan.out;

    component num_to_bits = Num2Bits(254);
    num_to_bits.in <== r;

    var r_msb = num_to_bits.out[253];

    r_msb === x_r;

    // for (var i=0; i<N; i++) {
    //     X[i] === XA[x_r][i];
    // }

    component eqs[A1_size];
    signal out[A1_size*N];

    k=0;
    for (var i=0; i<A1_size; i++) {
        eqs[i] = IsEqual();
        eqs[i].in[0] <== i;
        eqs[i].in[1] <== x_r;

        for (var j=0; j<N; j++) {
            out[k] <== eqs[i].out * XA[i][j];
            k++;

        }
    }

    component eqs2[N][A1_size*N]; 
    signal out2[N];
    component calcTotal[N];

    for (var k=0; k<N; k++) {
        calcTotal[k] = CalculateTotal(A1_size*N);
        for (var i=0; i<A1_size*N; i++) {
            eqs2[k][i] = IsEqual();
            eqs2[k][i].in[0] <== i;
            eqs2[k][i].in[1] <== x_r*N+k;

            calcTotal[k].nums[i] <== eqs2[k][i].out * out[i];
        }
        out2[k] <== calcTotal[k].sum;
    }

    for (var i=0; i<N; i++) {    
        out2[i] === X[i];
    }

}

component main {public [comm_XA, comm_X, comm_r]} = select_array(2, 2);