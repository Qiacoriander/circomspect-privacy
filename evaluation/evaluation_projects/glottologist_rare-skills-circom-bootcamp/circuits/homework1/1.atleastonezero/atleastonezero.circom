pragma circom 2.0.0;

template AtLeastOneZero(n) {
    signal input x[n];
    signal product[n+1];
    
    product[0] <== 1;
    for (var i = 0; i < n; i++) {
        product[i+1] <== product[i] * x[i];
    }
    
    product[n] === 0;
}

component main = AtLeastOneZero(3);
