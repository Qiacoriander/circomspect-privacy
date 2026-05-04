pragma circom 2.0.0;
include "../../node_modules/circomlib/circuits/comparators.circom";

template RemoveAirBubbles(W,H) {
    signal input grid[W][H];
    signal input onOff;

    signal notZeroFirstPositionEven[W][H][H];    
    signal isZeroFirstPositionEven[W][H][H];    
    signal notZeroSecondPositionEven[W][H][H];    
    signal isZeroSecondPositionEven[W][H][H];

    signal notZeroFirstPositionOdd[W][H][H];    
    signal isZeroFirstPositionOdd[W][H][H];    
    signal notZeroSecondPositionOdd[W][H][H];    
    signal isZeroSecondPositionOdd[W][H][H];

    component isZeroEven[W][H][H];
    component isZeroOdd[W][H][H];

    signal columnSortingEven[W][5][H];
    signal columnSortingOdd[W][5][H];
    // columnSortingOdd[0] <== column;
    signal output out[W][H];

    assert(onOff == 0 || onOff == 1);

    for(var i = 0; i < W; i++) {
        columnSortingOdd[i][0] <== grid[i];
        for(var j = 1; j < 5; j++) {
            for(var k = 0; k < H; k+=2) {
                isZeroEven[i][j][k] = IsZero();
                isZeroEven[i][j][k].in <== columnSortingOdd[i][j-1][k] + (1 - onOff);
                var isZeroOut = isZeroEven[i][j][k].out;

                notZeroFirstPositionEven[i][j][k] <== (1 - isZeroOut) * columnSortingOdd[i][j-1][k];
                isZeroFirstPositionEven[i][j][k] <== isZeroOut * columnSortingOdd[i][j-1][k+1];

                notZeroSecondPositionEven[i][j][k] <== (1 - isZeroOut) * columnSortingOdd[i][j-1][k+1];
                isZeroSecondPositionEven[i][j][k] <== isZeroOut * columnSortingOdd[i][j-1][k];

                columnSortingEven[i][j][k] <== notZeroFirstPositionEven[i][j][k] + isZeroFirstPositionEven[i][j][k];
                columnSortingEven[i][j][k+1] <== notZeroSecondPositionEven[i][j][k] + isZeroSecondPositionEven[i][j][k];
            }

            for(var l = 1; l < H-1; l+=2) {
                isZeroOdd[i][j][l] = IsZero();
                isZeroOdd[i][j][l].in <== columnSortingEven[i][j][l] + (1 - onOff);
                var isZeroOut = isZeroOdd[i][j][l].out;

                notZeroFirstPositionOdd[i][j][l] <== (1 - isZeroOut) * columnSortingEven[i][j][l];
                isZeroFirstPositionOdd[i][j][l] <== isZeroOut * columnSortingEven[i][j][l+1];

                notZeroSecondPositionOdd[i][j][l] <== (1 - isZeroOut) * columnSortingEven[i][j][l+1];
                isZeroSecondPositionOdd[i][j][l] <== isZeroOut * columnSortingEven[i][j][l];

                columnSortingOdd[i][j][l] <== notZeroFirstPositionOdd[i][j][l] + isZeroFirstPositionOdd[i][j][l];
                columnSortingOdd[i][j][l+1] <== notZeroSecondPositionOdd[i][j][l] + isZeroSecondPositionOdd[i][j][l];
            }
            columnSortingOdd[i][j][0] <== columnSortingEven[i][j][0];
            columnSortingOdd[i][j][H-1] <== columnSortingEven[i][j][H-1];
        }
        out[i] <== columnSortingEven[i][4];
    }
}
