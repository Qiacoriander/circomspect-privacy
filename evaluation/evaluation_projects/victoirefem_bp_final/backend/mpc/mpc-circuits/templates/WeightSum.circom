pragma circom 2.1.0;

template WeightSum(N) {
    
    signal input ai[N];
    signal input ri[N];
    signal output out;

    signal wsum[N];
    wsum[0] <== ai[0]*ri[0];
    for (var i = 1; i < N; i++){
        wsum[i] <== wsum[i-1] + ai[i]*ri[i];
    }
    
    out <== wsum[N-1];
}