pragma circom 2.1.6;

template Bits2Num(n){
    signal input in[n];
    signal output out;

    var value = 0;
    var pow = 1;
    for(var i=0;i<n;i++){
        in[i]*(1-in[i]) === 0;
        value += pow*in[i];
        pow +=pow;
    }
    out <== value;
}