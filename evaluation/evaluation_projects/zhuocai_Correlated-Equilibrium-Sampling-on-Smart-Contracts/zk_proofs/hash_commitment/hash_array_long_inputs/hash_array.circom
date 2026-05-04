pragma circom 2.0.0;
include "../../circomlib/circuits/comparators.circom";
include "../../circomlib/circuits/poseidon.circom";
/*This circuit template checks that commitment of array X is valid, i.e. hash(X) = comm

Public: comm
Private: X
*/  


template poseidon_ex(N) {  
    signal input inputs[N];  
    signal input comm;

    // component poseidon = Poseidon(N);
    // component poseidon;
    // component poseidon_2;
    // component poseidon_final;
    var num_comp_max = N/16;

    component poseidon[num_comp_max];
    var num_comp=0;
    var poseidon_out[16] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    var poseidon_out_add[16] = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

    for (var i=0; i<N; i+=16) {

        if (i==0) {
            poseidon[num_comp] = PoseidonEx(16, 16);

            poseidon[num_comp].initialState <== 0;
            

            for (var j=0; j<16; j++) {
                poseidon[num_comp].inputs[j] <== inputs[j];
            }

            for (var j=0; j<16; j++) {
                poseidon_out[j] = poseidon[num_comp].out[j];
                // log(poseidon_out[j]);
            }



            num_comp++;
            
        }
        else if (i == N-16) {
            poseidon[num_comp] = PoseidonEx(16, 1);
            poseidon[num_comp].initialState <== 0;

            for (var j=0; j<16; j++) {
                poseidon[num_comp].inputs[j] <== poseidon_out_add[j];
            }

            // poseidon_out = poseidon.out;
            // log(poseidon[num_comp].out[0]);

            // for (var j=0; j<16; j++) { 
            //     log(poseidon_out_add[j]);
            // }

            comm === poseidon[num_comp].out[0];  
            num_comp++;
        }
        else {

            poseidon[num_comp] = PoseidonEx(16, 16);
            poseidon[num_comp].initialState <== 0;

            for (var j=0; j<16; j++) {
                poseidon[num_comp].inputs[j] <== poseidon_out_add[j];
            }

             for (var j=0; j<16; j++) {
                poseidon_out[j] = poseidon[num_comp].out[j];
            }
            num_comp++;
        }

        var k=i+16;
        for (var j=0; j<16; j++) {
            if (k<N) {
                poseidon_out_add[j] = poseidon_out[j] + inputs[k];
                // log(poseidon_out_add[j]);
                k++;
            }   
        }

    } 

}

component main {public [comm]} = poseidon_ex(32);