pragma circom 2.1.8;
include "comparators.circom";
include "multiplexer.circom";


template Fibonacci(n) {
    signal input k;
    signal output out;
    
    assert (n > 1);
    signal valid_selector <== LessThan(252)([k, n]);
    valid_selector === 1;

    signal result[n+1];
    result[0] <== 1;
    result[1] <== 1;

    for(var i=2; i <= n; i++) {
        result[i] <== result[i-1] + result[i-2];
    }
    
    component mux = Multiplexer(1, n+1);

    for(var i=0; i <= n; i++) {
        mux.inp[i][0] <== result[i];
    }
    mux.sel <== k;
    out <== mux.out[0];
}

component main = Fibonacci(100);