pragma circom 2.0.0;
include "../../../node_modules/circomlib/circuits/comparators.circom";

// FILTER_YELLOW
template ArgumentsFilterYellow(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 1, 0, 0];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 31;

     for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut
    ];
}

// FILTER_RED
template ArgumentsFilterRed(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 2, 0, 0];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 32;

     for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut
    ];
}

// FILTER_BLUE
template ArgumentsFilterBlue(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 3, 0, 0];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 33;

     for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut
    ];
}
