pragma circom 2.0.0;
// include "../../exp_elliptic/circom-ecdsa/node_modules/circomlib/circuits/comparators.circom";
// include "../../exp_elliptic/circom-ecdsa/node_modules/circomlib/circuits/poseidon.circom";
include "../../circomlib/circuits/comparators.circom";
include "../../circomlib/circuits/poseidon.circom";

/*This circuit template checks that commitment of array X is valid, i.e. hash(X) = comm

Public: comm
Private: X
*/  


template Commitment_res(N) {  
    signal input inputs[N];  
    signal output comm;

    component poseidon = Poseidon(N);

    for (var i=0; i<N; i++) {
        poseidon.inputs[i] <== inputs[i];
    }
    // log(comm);
    // log(poseidon.out);
    comm<== poseidon.out;  
}

// component main {public [comm]} = Commitment(1);