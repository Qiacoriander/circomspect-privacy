pragma circom 2.1.6;

template Powers(n) {
    signal input a;
    signal output powers[n];
    
    powers[0] <== a;
    for (var i = 1; i < n; i++) {
        powers[i] <==  powers[i - 1] * a;
    }
}
component main = Powers(6);