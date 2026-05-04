pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/bitify.circom";

template AggregatedVote(n, kd, nCandiadates, nApproves, k){
    signal input in_d[nCandiadates];
    signal output d[kd];

    var sum = 0;
    for(var i=0; i<nCandiadates; i++){
        (in_d[i] - 1) * in_d[i] === 0;
        sum += in_d[i];
    }
    sum === nApproves;
    var d_bits[n*kd];
    for(var i=0; i<nCandiadates-1; i++){
        d_bits[k*i] = in_d[i];
        for(var j=1; j<k;j++){
            d_bits[k*i + j] = 0;
        }
    }
    d_bits[(nCandiadates-1)*k] = in_d[nCandiadates-1];
    for(var i=(nCandiadates-1)*k+1; i<n*kd;i++ ){
        d_bits[i] = 0;
    }
    component Bits2Num[kd];
    for(var i=0;i < kd; i++){
        Bits2Num[i] = Bits2Num(n);
        for(var j=0; j<n; j++){
            Bits2Num[i].in[j] <== d_bits[n*i + j];
        }
        d[i] <== Bits2Num[i].out; 
    } 
}


// component main {public [in_d]} = AggregatedVote(114, 2, 10, 5, 20);
