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



template AggregatedVote(n, kd, nCandiadates, S, k){
    signal input in_d[nCandiadates];
    signal output d[kd];

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
    var d_bits[n*kd];
    component Score2bits[nCandiadates];
    for(var i=0; i<nCandiadates; i++){
        Score2bits[i] = Num2Bits(k);
        Score2bits[i].in <== in_d[i];
        for(var j=0; j<k;j++){
            d_bits[k*i + j] = Score2bits[i].out[j];
        }
    }
    for(var i=nCandiadates*k; i<n*kd;i++ ){
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
