pragma circom 2.1.8;

include "comparators.circom";
include "multiplexer.circom";


template IsInRange(lower, upper) {
    signal input number;
    signal output out;
    signal is_valid_lower <== GreaterEqThan(252)([number, lower]);
    signal is_valid_upper <== LessThan(252)([number, upper]);
    out <== is_valid_lower * is_valid_upper;
}

template SwapElementsInArray(n) {
    assert (n > 0);
    
    signal input array[n];
    signal input j;
    signal input k;
    
    signal k_in_range <== IsInRange(0, n)(k);
    signal j_in_range <== IsInRange(0, n)(j);
    k_in_range === 1;
    j_in_range === 1;

    signal k_equal_j;
    k_equal_j <== IsEqual()([j, k]);

    signal output out[n];

    component mux_j = Multiplexer(1, n);
    for(var i = 0; i < n; i++) {
        mux_j.inp[i][0] <== array[i];
    }
    mux_j.sel <== j;

    component mux_k = Multiplexer(1, n);
    for(var i = 0; i < n; i++) {
        mux_k.inp[i][0] <== array[i];
    }
    mux_k.sel <== k;

    signal swapped[n];
    component isKIndex[n];
    component isJIndex[n];
    signal isNotEqual[n];


    signal branchJ[n];
    signal branchK[n];
    signal branchNorKJ[n];
    for(var i = 0; i < n; i++) {
        isJIndex[i] = IsEqual();
        isJIndex[i].in[0] <== i;
        isJIndex[i].in[1] <== j;

        isKIndex[i] = IsEqual();
        isKIndex[i].in[0] <== i;
        isKIndex[i].in[1] <== k;

        
        branchK[i] <== mux_j.out[0] * isKIndex[i].out;
        branchJ[i] <== mux_k.out[0] * isJIndex[i].out;
        branchNorKJ[i] <== (1 - k_equal_j) * (1 - isKIndex[i].out - isJIndex[i].out); 
        // branchNorKJ[i] <== 19; 
        swapped[i] <== array[i] * branchNorKJ[i] + branchJ[i] + branchK[i];
        // swapped[i] <== 223;
    }

    out <== swapped;
}

component main = SwapElementsInArray(10);