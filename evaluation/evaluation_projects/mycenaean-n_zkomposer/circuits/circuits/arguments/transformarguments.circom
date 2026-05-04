pragma circom 2.0.0;
include "../../../node_modules/circomlib/circuits/comparators.circom";

// TRANSFORM_YELLOW_RED
template ArgumentsTransformYellowRed(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 1, 2, 0];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 1;

    // if eq 1, then multiply identity
    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORM_YELLOW_BLUE
template ArgumentsTransformYellowBlue(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 1, 3, 0];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 2;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORM_RED_YELLOW
template ArgumentsTransformRedYellow(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 2, 1, 0];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 3;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORM_RED_BLUE
template ArgumentsTransformRedBlue(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 2, 3, 0];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 4;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORM_BLUE_YELLOW
template ArgumentsTransformBlueYellow(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 3, 1, 0];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 5;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORM_BLUE_RED
template ArgumentsTransformBlueRed(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 3, 2, 0];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 6;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}
