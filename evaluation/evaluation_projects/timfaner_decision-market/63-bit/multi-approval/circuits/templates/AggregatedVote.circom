pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/bitify.circom";

template AggregatedVote(nCandiadates, nApproves, k){
    signal input in_d[nCandiadates];
    signal output d;

    var sum = 0;
    for(var i=0; i<nCandiadates; i++){
        (in_d[i] - 1) * in_d[i] === 0;
        sum += in_d[i];
    }
    sum === nApproves;
    component Bits2Num = Bits2Num((nCandiadates-1)*k + 1);
    for(var i=0; i<nCandiadates-1; i++){
        Bits2Num.in[k*i] <== in_d[i];
        for(var j=1; j<k;j++){
            Bits2Num.in[k*i + j] <== 0;
        }
    }
    Bits2Num.in[(nCandiadates-1)*k] <== in_d[nCandiadates-1];
    d <== Bits2Num.out;
}

