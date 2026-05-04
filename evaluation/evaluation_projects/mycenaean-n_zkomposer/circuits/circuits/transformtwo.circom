pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/comparators.circom";

template CalculateTotal(n) {
    signal input in[n];
    signal output out;

    signal sums[n];

    sums[0] <== in[0];

    for (var i = 1; i < n; i++) {
        sums[i] <== sums[i-1] + in[i];
    }

    out <== sums[n-1];
}

// https://github.com/darkforest-eth/circuits/blob/master/perlin/QuinSelector.circom
template QuinSelector(choices) {
    signal input in[choices];
    signal input index;
    signal output out;
    
    // Ensure that index < choices
    component lessThan = LessThan(4);
    lessThan.in[0] <== index;
    lessThan.in[1] <== choices;
    lessThan.out === 1;

    component calcTotal = CalculateTotal(choices);
    component eqs[choices];

    // For each item, check whether its index equals the input index.
    for (var i = 0; i < choices; i ++) {
        eqs[i] = IsEqual();
        eqs[i].in[0] <== i;
        eqs[i].in[1] <== index;

        // eqs[i].out is 1 if the index matches. As such, at most one input to
        // calcTotal is not 0.
        calcTotal.in[i] <== eqs[i].out * in[i];
    }

    // Returns 0 + 0 + 0 + item
    out <== calcTotal.out;
}

template TransformTwo(W, H) {
    signal input grid[W][H];
    signal input onOff;
    signal input inColor;
    signal input outColorBot;
    signal input outColorTop;
    signal output out[W][H];

    assert(onOff == 0 || onOff == 1);

    signal inColoring <== (onOff * inColor) - (1 - onOff );
    signal outColoringBot <== (onOff * outColorBot) - (1 - onOff);
    signal outColoringTop <== (onOff * outColorTop) - (1 - onOff);
    
    signal perservedTupleBot[W][H];
    signal perservedTupleTop[W][H];
    
    signal mutatedTupleBot[W][H];
    signal mutatedTupleTop[W][H];

    signal output tupleList[W][H][2];

    component isEqCurr[W][H];
    component isEqPrev[W][H];
    component quinSelCurr[W][H];

    signal changeFlags[W][H];
    signal isEqOut[W][H];

    signal lastElOn[W];
    signal lastElOff[W];

    for (var i = 0; i < W; i++) {
        var noTransformations = 0;
        changeFlags[i][0] <== 0;
        tupleList[i][0][1] <== grid[i][0];
        // Int -> [Int, Int]
        for (var j = 1; j < H; j++) {
            quinSelCurr[i][j] = QuinSelector(H);
            quinSelCurr[i][j].in <== grid[i];
            var currentIndex = j - noTransformations;
            quinSelCurr[i][j].index <== currentIndex;

            isEqPrev[i][j] = IsEqual();
            isEqPrev[i][j].in[0] <== tupleList[i][j-1][1];
            isEqPrev[i][j].in[1] <== inColoring;

            // `changeFlags` equals 1 if transformation was made in the previous step.
            // This way we avoid an edge case where added element (`outColoringTop`) equals `inColoring` and transformation is made.
            isEqOut[i][j] <== (1 - changeFlags[i][j-1]) * isEqPrev[i][j].out;
            
            // Tuple of two out colors (`outColoringBot`, `outColoringTop`) 
            perservedTupleBot[i][j] <== (1 - isEqOut[i][j]) * tupleList[i][j-1][1];
            perservedTupleTop[i][j] <== (1 - isEqOut[i][j]) * quinSelCurr[i][j].out;

            // Tuple of two colors from input grid returned by `DoubleQuinSelector`
            mutatedTupleBot[i][j] <== isEqOut[i][j] * outColoringBot;
            mutatedTupleTop[i][j] <== isEqOut[i][j] * outColoringTop;

            tupleList[i][j][0] <== mutatedTupleBot[i][j] + perservedTupleBot[i][j];
            tupleList[i][j][1] <== mutatedTupleTop[i][j] + perservedTupleTop[i][j];

            changeFlags[i][j] <== isEqOut[i][j];
            noTransformations += isEqOut[i][j];
            out[i][j-1] <== tupleList[i][j][0];
        }
        lastElOn[i] <== onOff * tupleList[i][H-1][1];
        lastElOff[i] <== (1 - onOff) * grid[i][H-1];
        out[i][H-1] <== lastElOn[i] + lastElOff[i];
    }
}
