pragma circom 2.0.2;

include "../../circuits/ecdsa.circom";

template ECDSAPrivToPub_multiple(n, k, num_comp) {  
    signal input privkey[num_comp][k];
    signal input pubkey[num_comp][2][k];

    component ECDSAPrivToPub_single[num_comp];

    for (var i=0; i<num_comp; i++) {
        ECDSAPrivToPub_single[i] = ECDSAPrivToPub(n, k);

        for (var j=0; j<k; j++) {
            ECDSAPrivToPub_single[i].privkey[j] <== privkey[i][j];

            ECDSAPrivToPub_single[i].pubkey[0][j] <== pubkey[i][0][j];
            ECDSAPrivToPub_single[i].pubkey[1][j] <== pubkey[i][1][j];
        }
        
    }


}

component main {public [pubkey]} = ECDSAPrivToPub_multiple(64, 4, 2);
