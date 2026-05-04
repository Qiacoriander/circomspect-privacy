pragma circom 2.0.0;
include "../../../node_modules/circomlib/circuits/comparators.circom";

template ArgumentsTransformTwoYellowYellowRed(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 1, 1, 2];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 10;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

template ArgumentsTransformTwoYellowYellowBlue(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 1, 1, 3];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 11;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORMTWO_YELLOW_RED_YELLOW
template ArgumentsTransformTwoYellowRedYellow(C, ARG_LEN    ) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 1, 2, 1];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 12;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORMTWO_YELLOW_RED_BLUE
template ArgumentsTransformTwoYellowRedBlue(C, ARG_LEN  ) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 1, 2, 3];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 13;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }
    
    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}       

// TRANSFORMTWO_YELLOW_BLUE_YELLOW

template ArgumentsTransformTwoYellowBlueYellow(C, ARG_LEN   ) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 1, 3, 1];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 14;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORMTWO_YELLOW_BLUE_RED
template ArgumentsTransformTwoYellowBlueRed(C, ARG_LEN  ) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 1, 3, 2];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 15;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORMTWO_RED_RED_YELLOW
template ArgumentsTransformTwoRedRedYellow(C, ARG_LEN   ) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 2, 2, 1];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 16;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORMTWO_RED_RED_BLUE
template ArgumentsTransformTwoRedRedBlue(C, ARG_LEN ) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 2, 2, 3];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 17;

    for (var i = 0; i < ARG_LEN; i++) { 
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORMTWO_RED_YELLOW_RED  
template ArgumentsTransformTwoRedYellowRed(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 2, 1, 2];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 18;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORMTWO_RED_YELLOW_BLUE 
template ArgumentsTransformTwoRedYellowBlue(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 2, 1, 3];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 19;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

//TRANSFORMTWO_RED_BLUE_YELLOW
template ArgumentsTransformTwoRedBlueYellow(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 2, 3, 1];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 20;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }

    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORMTWO_RED_BLUE_RED
template ArgumentsTransformTwoRedBlueRed(C, ARG_LEN ) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 2, 3, 2];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 21;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }
    
    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}


// TRANSFORMTWO_BLUE_BLUE_YELLOW 
template ArgumentsTransformTwoBlueBlueYellow(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 3, 3, 1];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 22;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }
    
    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}   

// TRANSFORMTWO_BLUE_BLUE_RED
template ArgumentsTransformTwoBlueBlueRed(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 3, 3, 2];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 23;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }
    
    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORMTWO_BLUE_YELLOW_BLUE
template ArgumentsTransformTwoBlueYellowBlue(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 3, 1, 3];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 24;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }
    
    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORMTWO_BLUE_YELLOW_RED
template ArgumentsTransformTwoBlueYellowRed(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 3, 1, 2];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 25;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }
    
    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORMTWO_BLUE_RED_YELLOW
template ArgumentsTransformTwoBlueRedYellow(C, ARG_LEN) {  
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 3, 2, 1];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 26;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }
    
    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}

// TRANSFORMTWO_BLUE_RED_BLUE
template ArgumentsTransformTwoBlueRedBlue(C, ARG_LEN) {
    signal input inputIndex;
    signal output out[C][ARG_LEN];
    signal instruction[ARG_LEN] <== [1, 3, 2, 3];
    signal instructionOut[ARG_LEN]; 

    component isEq;
    isEq = IsEqual();
    isEq.in[0] <== inputIndex;
    isEq.in[1] <== 27;

    for (var i = 0; i < ARG_LEN; i++) {
        instructionOut[i] <== instruction[i] * isEq.out;
    }
    
    out <== [
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        instructionOut,
        [0, 0, 0, 0],
        [0, 0, 0, 0]
    ];
}
