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
        swapped[i] <== array[i] * branchNorKJ[i] + branchJ[i] + branchK[i];
    }

    out <== swapped;
}

template MinElementIndexInArrayFromStartingIndex(n, start) {
    assert (n > 0);
    assert (start >= 0);
    assert (start < n);
    signal input numbers[n];

    var min = numbers[start];
    var minIndex = start;
    for (var i = start+1; i < n; i++) {
        min = min < numbers[i] ? min : numbers[i];
        minIndex = min < numbers[i] ? minIndex : i;
    }

    signal minSignal <-- min;
    signal minIndexSignal <-- minIndex;
    signal output out;
    component isSmaller[n];
    component EQ[n];

    var acc;
    for (var i = start; i < n; i++) {
        isSmaller[i] = LessEqThan(252);
        isSmaller[i].in[0] <== minSignal;
        isSmaller[i].in[1] <== numbers[i];
        isSmaller[i].out === 1;

        EQ[i] = IsEqual();
        EQ[i].in[0] <== minSignal;
        EQ[i].in[1] <== numbers[i];
        acc += EQ[i].out;
    }

    component zero;
    zero = IsEqual();
    zero.in[0] <== acc;
    zero.in[1] <== 0;
    zero.out === 0;
    out <== minIndexSignal;
}

template SelectionSort(n) {
    signal input array[n];
    signal output out[n];
    
    signal swap[n][n];
    component minIndex[n-1];
    component swapper[n];

    for (var i = 0; i < n; i++) {
        swap[0][i] <== array[i];
    }

    for (var i = 1; i < n; i++) {
        minIndex[i-1] = MinElementIndexInArrayFromStartingIndex(n, i-1);
        swapper[i-1] = SwapElementsInArray(n);

        for (var j = 0; j < n; j++) {
            minIndex[i-1].numbers[j] <== swap[i-1][j];
            swapper[i-1].array[j] <== swap[i-1][j];
        }
        swapper[i-1].j <== i-1;
        swapper[i-1].k <== minIndex[i-1].out;

        for (var j = 0; j < n; j++) {
            swap[i][j] <== swapper[i-1].out[j];
        }
    }
    
    for (var i = 0; i < n-1; i++) {
        // out[i] <== swap[n-4][i];
        out[i] <== minIndex[i].out;
        // out[i] <== swap[1][i];
        // out[i] <== swap[7][i];
    }
}

component main = SelectionSort(10);