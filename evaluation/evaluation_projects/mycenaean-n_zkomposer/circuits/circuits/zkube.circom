pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/comparators.circom";
include "./transform.circom";
include "./stack.circom";
include "./transformtwo.circom";
include "./reject.circom";
include "./filter.circom";
include "./arguments/argumentsaggregator.circom";

template Contains(LEN) {
    signal input element;
    signal input inArray[LEN];
    signal output outArray[LEN];
    signal output out;
    signal counter[LEN];
    component isEq[LEN];
    component isZero;

    isEq[0] = IsEqual();
    isEq[0].in[0] <== element;
    isEq[0].in[1] <== inArray[0];
    counter[0] <== isEq[0].out;
    outArray[0] <== inArray[0] * (1 - isEq[0].out);
    for (var i = 1; i < LEN; i++) {
        isEq[i] = IsEqual();
        isEq[i].in[0] <== element;
        isEq[i].in[1] <== inArray[i];
        counter[i] <== counter[i-1] + isEq[i].out;
        // removing a selected function from the available functions
        outArray[i] <== inArray[i] * (1 - isEq[i].out);
    }
    isZero = IsZero();
    isZero.in <== counter[LEN-1];
    out <== 1 - isZero.out;
}

template ZKube(W, H, C, NUM_AVAILABLE_ARGS, NUM_TOTAL_ARGS, ARG_LEN) {
    // public
    signal input initialGrid[W][H];
    signal input finalGrid[W][H];
    // C possible selected transformations is arbitrary
    signal input selectedFunctionsIndexes[C];
    signal input availableFunctionsIndexes[NUM_AVAILABLE_ARGS];
    signal input account;

    signal finalGridForPlayer[W][H];
    
    component transform[C];
    component stack[C];
    component transformTwo[C];
    component reject[C];
    component filter[C];

    component contains[C];
    signal intermediateAvailableFunctionsIndexes[C+1][NUM_AVAILABLE_ARGS];
    // having +1 because we are assigning current value to the next one
    intermediateAvailableFunctionsIndexes[0] <== availableFunctionsIndexes;
    
    // C intermediate grids, corresponding to possible Functions. Of width W and height H
    signal intermediateGrids[C+1][W][H];
    intermediateGrids[0] <== initialGrid;
    signal selectedFunctions[C][C][ARG_LEN];
    component argumentsAggregator[C];
    for (var i = 0; i < C; i++) {
        // check that player has not selected any of the functions which is not available for the puzzle
        // since `selectedFunctionsIndexes` is private signal we can only check the 
        // `selectedFunctionsIndexes` should be a subset of `availableFunctionsIndexes` 
        contains[i] = Contains(NUM_AVAILABLE_ARGS);
        contains[i].element <== selectedFunctionsIndexes[i];
        contains[i].inArray <== intermediateAvailableFunctionsIndexes[i];
        intermediateAvailableFunctionsIndexes[i+1] <== contains[i].outArray;
        assert(contains[i].out > 0);

        argumentsAggregator[i] = ArgumentsAggregator(NUM_TOTAL_ARGS+1, C, ARG_LEN);
        argumentsAggregator[i].index <== selectedFunctionsIndexes[i];
        selectedFunctions[i] <== argumentsAggregator[i].out;

        transform[i] = Transform(W, H);
        transform[i].grid <== intermediateGrids[i];
        transform[i].onOff <== selectedFunctions[i][0][0];
        transform[i].inColor <== selectedFunctions[i][0][1];
        transform[i].outColor <== selectedFunctions[i][0][2];

        stack[i] = Stack(W, H);
        stack[i].grid <== transform[i].out;
        stack[i].onOff <== selectedFunctions[i][1][0];
        stack[i].color <== selectedFunctions[i][1][1];

        transformTwo[i] = TransformTwo(W, H);
        transformTwo[i].grid <== stack[i].out;
        transformTwo[i].onOff <== selectedFunctions[i][2][0];
        transformTwo[i].inColor <== selectedFunctions[i][2][1];
        transformTwo[i].outColorBot <== selectedFunctions[i][2][2];
        transformTwo[i].outColorTop <== selectedFunctions[i][2][3];
        
        reject[i] = Reject(W, H);
        reject[i].grid <== transformTwo[i].out;
        reject[i].onOff <== selectedFunctions[i][3][0];
        reject[i].color <== selectedFunctions[i][3][1];

        filter[i] = Filter(W, H);
        filter[i].grid <== reject[i].out;
        filter[i].onOff <== selectedFunctions[i][4][0];
        filter[i].color <== selectedFunctions[i][4][1];

        intermediateGrids[i + 1] <== filter[i].out;
    }

    finalGridForPlayer <== intermediateGrids[C];

    component isEq[W][H];
    var counter = 0;
    for (var i = 0; i < W; i++) {
        for (var j = 0; j < H; j++) {
            isEq[i][j] = IsEqual();
            isEq[i][j].in[0] <== finalGridForPlayer[i][j];
            isEq[i][j].in[1] <== finalGrid[i][j];
            counter += isEq[i][j].out;
        }
    }

    component eqCheck;
    // compairng the final results
    eqCheck = ForceEqualIfEnabled();
    // if not equal no proof, sorry
    eqCheck.enabled <== 1;
    eqCheck.in[0] <== counter;
    eqCheck.in[1] <== W*H;
}

// W = grid width
// H = grid height
// C = number of transformation circuits (transform, stack, transformTwo, reject, filter)
// NUM_AVAILABLE_ARGS = number of functions in a round
// NUM_TOTAL_ARGS = all available arguments to zKube circuit with 4 available colors and 5 available transformation circuits (transform, stack, transformTwo, reject, filter)
// ARG_LEN = length of arguments for each transformation circuit
component main { public [initialGrid, finalGrid, availableFunctionsIndexes, account] } = ZKube(8, 12, 5, 8, 33, 4);
