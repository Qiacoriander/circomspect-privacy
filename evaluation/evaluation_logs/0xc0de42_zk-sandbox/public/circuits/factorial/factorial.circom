pragma circom 2.1.8;
include "comparators.circom";
include "multiplexer.circom";


template Factorial(n) {
    assert (n > 0);
    signal input k;
    signal output out;

    signal valid_selector <== LessThan(252)([k, n]);
    valid_selector === 1;
    
    signal result[n+1];
    result[0] <== 1;

    for(var i = 1; i <= n; i++) {
        result[i] <== result[i-1] * i;
    }

    component mux = Multiplexer(1, n+1);
    for(var i = 0; i < n+1; i++) {
        mux.inp[i][0] <== result[i];
    }
    mux.sel <== k;
    out <== mux.out[0];
}

component main = Factorial(100);