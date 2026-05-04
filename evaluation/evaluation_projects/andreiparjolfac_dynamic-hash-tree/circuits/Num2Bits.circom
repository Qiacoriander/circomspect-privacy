pragma circom 2.1.6;

template Num2Bits(n){
    signal input in;
    signal output out[n];

    var value = 0;
    var pow = 1;
    for(var i=0;i<n;i++){
        out[i] <-- (in>>i)&1;
        out[i]*(1-out[i]) === 0;
        value += out[i]*pow;
        pow += pow;
    }

    value === in;

}