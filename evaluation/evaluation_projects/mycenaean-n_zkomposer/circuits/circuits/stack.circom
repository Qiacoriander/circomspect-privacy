pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/comparators.circom";

template Stack(W, H) {
    signal input grid[W][H];
    signal input onOff;
    signal input color;
    signal output out[W][H];

    assert(onOff == 0 || onOff == 1);

    signal stack[W][H];
    signal stackColoring <== onOff * color;

    component isZeroStack[W][H];
    component gtZeroStack[W][H];

    for (var i = 0; i < W; i++) {
        stack[i][0] <== 0;
        for (var j = 1; j < H; j++) {
            var prevIndex = j - 1;

            // checking for == 0
            isZeroStack[i][j] = IsZero();
            isZeroStack[i][j].in <== grid[i][j];

            // checking for gt 0
            gtZeroStack[i][j] = GreaterThan(4);
            gtZeroStack[i][j].in[0] <== grid[i][prevIndex];
            gtZeroStack[i][j].in[1] <== 0;

            stack[i][j] <== isZeroStack[i][j].out * gtZeroStack[i][j].out;
            out[i][prevIndex] <== grid[i][prevIndex] + stack[i][prevIndex]  * stackColoring;
        }
        out[i][H - 1] <== grid[i][H - 1] + stack[i][H - 1] * stackColoring;
    }
}
