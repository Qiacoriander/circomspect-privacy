pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/comparators.circom";

template Transform(W, H) {
    signal input grid[W][H];
    signal input onOff;
    // type(): 0 (do not transform, but perserve) | 1 | 2 | 3
    signal input inColor;
    // type(): 0 (do not transform, but perserve) | 1 | 2 | 3
    signal input outColor;
    signal output out[W][H];

    assert(onOff == 0 || onOff == 1);

    signal transformInColoring <== onOff * inColor;
    signal transformOutColoring <== onOff * outColor;
    signal margin[W][H];
    signal mask[W][H];

    component isEq[W][H];
    
    for (var i = 0; i < W; i++) {
        for (var j = 0; j < H; j++) {
            // checking for == 1
            // 1st step
            margin[i][j] <== transformOutColoring - grid[i][j];
            // 2nd step
            isEq[i][j] = IsEqual();
            isEq[i][j].in[0] <== grid[i][j];
            isEq[i][j].in[1] <== transformInColoring;
            // 3rd step
            mask[i][j] <== isEq[i][j].out * margin[i][j];
            // 4th step
            out[i][j] <== grid[i][j] + mask[i][j];
        }
    }
}
