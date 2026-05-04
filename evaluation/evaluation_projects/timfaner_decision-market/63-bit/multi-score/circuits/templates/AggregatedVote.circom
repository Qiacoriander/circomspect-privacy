pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/bitify.circom";



function size(a) {
    if (a==0) {
        return 0;
    }
    var n = 1;
    var r = 1;
    while (n<a) {
        r++;
        n *= 2;
    }
    return r;
}



template AggregatedVote(nCandiadates, S, k){
    signal input in_d[nCandiadates];
    signal output d;

    var sizeS = size(S);

    component scoreComp0[nCandiadates];
    component scoreCompS[nCandiadates];
    var sum = 0;
    for(var i=0; i<nCandiadates; i++){
        scoreComp0[i] = GreaterEqThan(sizeS);
        scoreComp0[i].in[0] <== in_d[i];
        scoreComp0[i].in[1] <== 0;
        scoreComp0[i].out === 1;
        scoreCompS[i] = LessEqThan(sizeS);
        scoreCompS[i].in[0] <== in_d[i];
        scoreCompS[i].in[1] <== S;
        scoreCompS[i].out === 1;
        sum += in_d[i];
    }
    sum === S;
    component Bits2Num = Bits2Num(nCandiadates*k);
    component d2bits[nCandiadates];

    for(var i=0; i<nCandiadates; i++){
        d2bits[i] = Num2Bits(k);
        d2bits[i].in <== in_d[i];
        for(var j=0; j<k;j++){
            Bits2Num.in[k*i + j] <== d2bits[i].out[j];
        }
    }
    d <== Bits2Num.out;
}

