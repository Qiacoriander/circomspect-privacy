pragma circom 2.1.8;
include "comparators.circom";
include "multiplexer.circom";


template Pow(max_power) {
    assert(max_power > 0);
    signal input a[2];
    signal output c;

    signal valid_input <== LessEqThan(252)([a[1], max_power]);
    valid_input === 1;

    signal result[max_power+1];
    result[0] <== 1;
    for(var i = 1; i <= max_power; i++) {
        result[i] <== result[i-1] * a[0];
    }
    component mux = Multiplexer(1, max_power+1);

    for(var i = 0; i <= max_power; i++) {
        mux.inp[i][0] <== result[i];
    }
    mux.sel <== a[1];
    c <== mux.out[0];
}

component main = Pow(10);